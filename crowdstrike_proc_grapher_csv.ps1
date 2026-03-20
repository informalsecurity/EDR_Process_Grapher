# ============================================================
#  Convert-CrowdStrikeToProcessTree.ps1
#  Converts CrowdStrike Falcon Advanced Event Search (Humio)
#  CSV exports into process-tree JSON files consumable by
#  the Process Tree Viewer HTML tool.
# ============================================================

$file_path = Read-Host "Provide the full path to the folder containing CrowdStrike CSV export file(s)"
$files = Get-ChildItem $file_path -Recurse -Filter *.csv
$fcount = $files.Count
$counter = 0

# -------------------------------------------------------
# Process key: aid + TargetProcessId
# CrowdStrike TargetProcessId is a unique 64-bit kernel
# process ID — no timestamp needed to disambiguate.
# -------------------------------------------------------
function Make-ProcessKey {
    param([string]$Aid, [string]$ProcessId)
    if ([string]::IsNullOrWhiteSpace($ProcessId) -or $ProcessId -eq "0") { return $null }
    # Strip scientific notation if Excel mangled the value
    try {
        $pid_clean = [string][long][double]$ProcessId
    } catch {
        $pid_clean = $ProcessId.Trim()
    }
    if ([string]::IsNullOrWhiteSpace($pid_clean) -or $pid_clean -eq "0") { return $null }
    return ($Aid + "_" + $pid_clean).ToUpper()
}

# -------------------------------------------------------
# Convert CrowdStrike unix timestamp (seconds or ms) to ISO
# -------------------------------------------------------
function Convert-CSTimestamp([string]$ts) {
    if ([string]::IsNullOrWhiteSpace($ts)) { return "" }
    try {
        $d = [double]$ts
        # If > 1e12 it's milliseconds, otherwise seconds
        if ($d -gt 1000000000000) { $d = $d / 1000 }
        return [System.DateTimeOffset]::FromUnixTimeMilliseconds([long]($d * 1000)).ToString("yyyy-MM-ddTHH:mm:ss.fff")
    } catch { return $ts }
}

# -------------------------------------------------------
# Extract filename from a full device path
# e.g. \Device\HarddiskVolume3\Windows\System32\cmd.exe -> CMD.EXE
# -------------------------------------------------------
function Get-BaseName([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return "" }
    $path = $path.Trim()
    $idx = $path.LastIndexOfAny([char[]]@([char]92, [char]47))
    if ($idx -ge 0) { return $path.Substring($idx + 1).ToUpper().Trim() }
    return $path.ToUpper().Trim()
}

# -------------------------------------------------------
# Add unique value to a hashtable of HashSets
# -------------------------------------------------------
function Add-Unique {
    param($dict, [string]$key, [string]$value)
    if ([string]::IsNullOrWhiteSpace($key))   { return }
    if ([string]::IsNullOrWhiteSpace($value)) { return }
    if (-not $dict.ContainsKey($key)) { $dict[$key] = [System.Collections.Generic.HashSet[string]]::new() }
    [void]$dict[$key].Add($value)
}

function Set-IfMissing {
    param($dict, [string]$key, [string]$value)
    if ([string]::IsNullOrWhiteSpace($key)) { return }
    if (-not $dict.ContainsKey($key)) { $dict[$key] = $value }
}

# -------------------------------------------------------
# JSON escape - uses string,string overload explicitly
# -------------------------------------------------------
function EscJ([string]$s) {
    if ($null -eq $s) { return "" }
    $s = [string]$s
    $s = $s.Replace([string][char]92, [string][char]92 + [string][char]92)
    $s = $s.Replace([string][char]34, [string][char]92 + [string][char]34)
    $s = $s.Replace([string][char]13, "")
    $s = $s.Replace([string][char]10, "")
    $s = $s.Replace([string][char]9,  " ")
    return $s
}

# -------------------------------------------------------
# Iterative cycle-breaker
# -------------------------------------------------------
function Remove-Cycles($pid_dict) {
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $inStack = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($startKey in @($pid_dict.Keys)) {
        if ($visited.Contains($startKey)) { continue }
        $stack    = [System.Collections.Generic.Stack[string]]::new()
        $idxStack = [System.Collections.Generic.Stack[int]]::new()
        $stack.Push($startKey); $idxStack.Push(0)
        [void]$visited.Add($startKey); [void]$inStack.Add($startKey)
        while ($stack.Count -gt 0) {
            $cur  = $stack.Peek()
            $idx  = $idxStack.Pop()
            $kids = if ($pid_dict.ContainsKey($cur)) { @($pid_dict[$cur]) } else { @() }
            $advanced = $false
            while ($idx -lt $kids.Count) {
                $child = $kids[$idx]; $idx++
                if ($inStack.Contains($child)) { [void]$pid_dict[$cur].Remove($child); continue }
                if (-not $visited.Contains($child)) {
                    [void]$visited.Add($child); [void]$inStack.Add($child)
                    $idxStack.Push($idx)
                    $stack.Push($child); $idxStack.Push(0)
                    $advanced = $true; break
                }
            }
            if (-not $advanced) { [void]$stack.Pop(); [void]$inStack.Remove($cur) }
        }
    }
}

# -------------------------------------------------------
# Event classification
# -------------------------------------------------------
$ProcessEvents = [System.Collections.Generic.HashSet[string]]@(
    "ProcessRollup2", "SyntheticProcessRollup2"
)

function Is-NetworkEvent([string]$name) {
    return $name -match "^Network(Connect|Listen|Receive|Transmit)"
}

function Is-FileWriteEvent([string]$name) {
    return $name -match "Written"
}

# ==================================================================
# Main loop
# ==================================================================
foreach ($file in $files) {
    $counter++
    Write-Host "Working on $counter of $fcount - $($file.FullName)"

    $pid_dict      = @{}
    $pid_user_dict = @{}
    $pid_dns       = @{}
    $pid_connect   = @{}
    $pid_create    = @{}
    $pid_time      = @{}
    $cli_dict      = @{}
    $pname_dict    = @{}
    $hashes_dict   = @{}
    $rules_dict    = @{}

    $system_name = ($file.Name -replace "\.csv$", "")

    Write-Host "  Reading CSV..."
    $rows = Import-Csv -Path $file.FullName
    Write-Host "  Processing $($rows.Count) rows..."

    foreach ($row in $rows) {
        $aid         = $row."aid"
        $eventName   = $row."#event_simpleName".Trim()
        $computerName = $row."ComputerName"

        if ($ProcessEvents.Contains($eventName)) {
            # ── ProcessRollup2: build tree nodes ──────────────────
            $targetId   = $row."TargetProcessId"
            $sourceId   = $row."SourceProcessId"    # = ParentProcessId
            $parentId   = $row."ParentProcessId"    # same value, belt+suspenders
            if ([string]::IsNullOrWhiteSpace($sourceId)) { $sourceId = $parentId }

            $childKey  = Make-ProcessKey -Aid $aid -ProcessId $targetId
            $parentKey = Make-ProcessKey -Aid $aid -ProcessId $sourceId

            $imagePath   = $row."ImageFileName"
            $procName    = Get-BaseName $imagePath
            $parentName  = if ($row."ParentBaseFileName") { $row."ParentBaseFileName".ToUpper().Trim() } else { "" }
            $cli         = if ($row."CommandLine")        { $row."CommandLine".ToUpper().Trim() }         else { "" }
            $sha256      = if ($row."SHA256HashData")     { $row."SHA256HashData".ToUpper().Trim() }      else { "" }
            $userName    = if ($row."UserName")           { $row."UserName".ToUpper().Trim() }            else { "" }
            $procStart   = $row."ProcessStartTime"
            $isoTime     = Convert-CSTimestamp $procStart

            # Tactic/Technique as rules
            $tactic      = if ($row."Tactic")      { $row."Tactic".Trim() }      else { "" }
            $technique   = if ($row."Technique")   { $row."Technique".Trim() }   else { "" }
            $techId      = if ($row."TechniqueId") { $row."TechniqueId".Trim() } else { "" }

            if ($childKey) {
                Set-IfMissing $pid_time  $childKey $isoTime
                if ($procName  -ne "") { Add-Unique $pname_dict $childKey $procName }
                if ($cli       -ne "") { Add-Unique $cli_dict   $childKey $cli }
                if ($userName  -ne "") { Add-Unique $pid_user_dict $childKey $userName }
                if ($sha256    -ne "" -and -not $hashes_dict.ContainsKey($childKey)) { $hashes_dict[$childKey] = $sha256 }
                if ($eventName -ne "") { Add-Unique $rules_dict $childKey $eventName }
                if ($tactic    -ne "") { Add-Unique $rules_dict $childKey $tactic }
                if ($techId    -ne "") { Add-Unique $rules_dict $childKey "$techId - $technique" }
            }
            if ($parentKey) {
                if ($parentName -ne "") { Add-Unique $pname_dict $parentKey $parentName }
            }
            if ($parentKey -and $childKey -and $parentKey -ne $childKey) {
                Add-Unique $pid_dict $parentKey $childKey
            }

        } else {
            # ── Non-process events: attach activity to actor process ──
            # Actor is identified by ContextProcessId
            $ctxId    = $row."ContextProcessId"
            $actorKey = Make-ProcessKey -Aid $aid -ProcessId $ctxId

            if (-not $actorKey) { continue }

            # Record the actor process name from ContextBaseFileName
            # This ensures processes only seen in non-ProcessRollup2 events still get a name
            $ctxName = $row."ContextBaseFileName"
            if (-not [string]::IsNullOrWhiteSpace($ctxName)) {
                Add-Unique $pname_dict $actorKey $ctxName.ToUpper().Trim()
            }

            # Record event type as a rule on the actor
            if ($eventName -ne "") { Add-Unique $rules_dict $actorKey $eventName }

            # Also record tactic/technique if present
            $tactic  = if ($row."Tactic")      { $row."Tactic".Trim() }      else { "" }
            $techId  = if ($row."TechniqueId") { $row."TechniqueId".Trim() } else { "" }
            $tech    = if ($row."Technique")   { $row."Technique".Trim() }   else { "" }
            if ($tactic -ne "") { Add-Unique $rules_dict $actorKey $tactic }
            if ($techId -ne "") { Add-Unique $rules_dict $actorKey "$techId - $tech" }

            # Network events
            if (Is-NetworkEvent $eventName) {
                $remoteIp   = $row."RemoteAddressIP4"
                if ([string]::IsNullOrWhiteSpace($remoteIp)) { $remoteIp = $row."RemoteAddressString" }
                $remotePort = $row."RemotePort"
                if (-not [string]::IsNullOrWhiteSpace($remoteIp) -and $remoteIp -ne "0.0.0.0") {
                    $remote = $remoteIp + ":" + $remotePort
                    Add-Unique $pid_connect $actorKey $remote.Trim(":")
                }
            }

            # DNS events
            if ($eventName -eq "DnsRequest") {
                $domain = $row."DomainName"
                if (-not [string]::IsNullOrWhiteSpace($domain)) {
                    Add-Unique $pid_dns $actorKey $domain.ToUpper().Trim()
                }
            }

            # File write events
            if (Is-FileWriteEvent $eventName) {
                # TargetFileName in the flat CSV already has the full path
                # e.g. \Device\HarddiskVolume3\Windows\Installerµ3ab.msi
                # Read it as a raw string via a temp variable to prevent
                # PowerShell from interpreting backslashes
                $tfn = [string]($row."TargetFileName")
                $fp  = [string]($row."FilePath")
                $fn  = [string]($row."FileName")

                $fullPath = ""

                # Prefer TargetFileName if it contains a backslash (full path)
                if ($tfn.Length -gt 1 -and $tfn.Contains([string][char]92)) {
                    $fullPath = $tfn.ToUpper()
                } elseif ($fp.Length -gt 1 -and $fn.Length -gt 0) {
                    # Combine FilePath + FileName
                    $cleanFp = $fp.TrimEnd([char]92)
                    $fullPath = ($cleanFp + [string][char]92 + $fn).ToUpper()
                } elseif ($tfn.Length -gt 1) {
                    $fullPath = $tfn.ToUpper()
                } elseif ($fn.Length -gt 1) {
                    $fullPath = $fn.ToUpper()
                }

                if ($fullPath.Length -gt 1) {
                    Add-Unique $pid_create $actorKey $fullPath
                }
            }
        }
    }

    Write-Host "  Detecting and removing cycles..."
    Remove-Cycles $pid_dict

    Write-Host "  Finding root processes..."
    $allChildKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($key in $pid_dict.Keys) { foreach ($child in $pid_dict[$key]) { [void]$allChildKeys.Add($child) } }

    $top_level = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $pid_dict.Keys) {
        if (-not $allChildKeys.Contains($key)) { [void]$top_level.Add($key) }
    }
    # Promote interesting orphans (network/dns activity but no parent edge seen)
    foreach ($key in $pname_dict.Keys) {
        if ($top_level.Contains($key)) { continue }
        $interesting = (($pid_connect[$key] -ne $null -and $pid_connect[$key].Count -gt 0) -or
                        ($pid_dns[$key]     -ne $null -and $pid_dns[$key].Count     -gt 0))
        if ($interesting -and -not $allChildKeys.Contains($key)) { [void]$top_level.Add($key) }
    }
    $top_level = @($top_level | Sort-Object | Get-Unique)

    Write-Host "  Building node data..."
    $allKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($k in $pname_dict.Keys) { [void]$allKeys.Add($k) }
    foreach ($k in $pid_dict.Keys)   { [void]$allKeys.Add($k) }

    $nodeMap = @{}
    foreach ($key in $allKeys) {
        $pname = if ($pname_dict[$key] -and $pname_dict[$key].Count -gt 0) { @($pname_dict[$key])[0] } else { "Unknown" }
        $puser = if ($pid_user_dict[$key] -and $pid_user_dict[$key].Count -gt 0) { ($pid_user_dict[$key] | Sort-Object) -join ", " } else { "Unknown" }
        $phash = if ($hashes_dict[$key])  { $hashes_dict[$key] } else { "Unknown" }
        $cli   = if ($cli_dict[$key] -and $cli_dict[$key].Count -gt 0) { @($cli_dict[$key])[0] } else { "Unknown" }
        $ptime = if ($pid_time[$key])     { $pid_time[$key] }    else { "Unknown" }

        $files       = if ($pid_create[$key]  -and $pid_create[$key].Count  -gt 0) { @($pid_create[$key])  } else { @() }
        $connections = if ($pid_connect[$key] -and $pid_connect[$key].Count -gt 0) { @($pid_connect[$key]) } else { @() }
        $queries     = if ($pid_dns[$key]     -and $pid_dns[$key].Count     -gt 0) { @($pid_dns[$key])     } else { @() }
        $rules       = if ($rules_dict[$key]  -and $rules_dict[$key].Count  -gt 0) { @($rules_dict[$key])  } else { @() }

        $hasEdges    = $pid_dict.ContainsKey($key) -and $pid_dict[$key].Count -gt 0
        $hasActivity = ($files.Count + $connections.Count + $queries.Count + $rules.Count) -gt 0
        $hasInfo     = ($pname -ne "Unknown") -or ($puser -ne "Unknown") -or ($cli -ne "Unknown")
        if (-not ($hasEdges -or $hasActivity -or $hasInfo)) { continue }

        $nodeMap[$key] = @{
            name                = $pname
            pid                 = $key
            sha256              = $phash
            creation_time       = $ptime
            user                = $puser
            commandline         = $cli
            files_created       = $files
            network_connections = $connections
            dns_queries         = $queries
            sysmon_rules        = $rules
            process_injections  = @()
        }
    }

    # ── Exclusion prompt ──────────────────────────────────────────
    $validRootKeys = @($top_level | Where-Object { $nodeMap.ContainsKey($_) })
    $topLevelNames = @($validRootKeys | ForEach-Object { $nodeMap[$_].name } | Sort-Object | Get-Unique)

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  TOP-LEVEL PROCESSES for: $system_name"
    Write-Host "  $($topLevelNames.Count) unique process name(s) found:"
    Write-Host "------------------------------------------------------------"
    $i = 1
    foreach ($n in $topLevelNames) {
        $instCount = @($validRootKeys | Where-Object { $nodeMap[$_].name -eq $n }).Count
        Write-Host ("  {0,3}.  {1}  ({2} instance{3})" -f $i, $n, $instCount, $(if ($instCount -ne 1){"s"}else{""}))
        $i++
    }
    Write-Host "============================================================"
    Write-Host ""
    Write-Host "  Enter process names to EXCLUDE (comma-separated), or press ENTER to keep all:"
    $excludeInput = Read-Host "  Exclude"
    $excludeNames = @()
    if (-not [string]::IsNullOrWhiteSpace($excludeInput)) {
        $excludeNames = @($excludeInput -split "," | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ -ne "" })
    }
    if ($excludeNames.Count -gt 0) {
        Write-Host "  Excluding: $($excludeNames -join ', ')"
        $validRootKeys = @($validRootKeys | Where-Object { $excludeNames -notcontains $nodeMap[$_].name })
        Write-Host "  $($validRootKeys.Count) top-level process(es) remaining."
    } else {
        Write-Host "  No exclusions applied."
    }
    Write-Host ""

    # ── Write JSON ────────────────────────────────────────────────
    $ofile = Join-Path $file_path ($system_name + "_processtree.json")
    if (Test-Path $ofile) { Remove-Item $ofile -Force }
    Write-Host "  Writing $ofile ..."
    $writer = [System.IO.StreamWriter]::new($ofile, $false, [System.Text.Encoding]::UTF8)

    $writer.WriteLine("{")
    $writer.WriteLine('  "name": "root",')
    $writer.WriteLine('  "pid": 0,')
    $writer.WriteLine('  "sha256": [],')
    $writer.WriteLine('  "user": "SYSTEM",')
    $writer.WriteLine('  "commandline": "SYSTEM PROCESS",')
    $writer.WriteLine('  "files_created": [],')
    $writer.WriteLine('  "network_connections": [],')
    $writer.WriteLine('  "dns_queries": [],')
    $writer.WriteLine('  "sysmon_rules": [],')
    $writer.WriteLine('  "process_injections": [],')
    $writer.WriteLine('  "children": [')

    $stack  = [System.Collections.Generic.Stack[object[]]]::new()
    $opened = [System.Collections.Generic.HashSet[string]]::new()

    for ($i = $validRootKeys.Count - 1; $i -ge 0; $i--) {
        $stack.Push(@($validRootKeys[$i], 2))
    }

    while ($stack.Count -gt 0) {
        $frame  = $stack.Pop()
        $key    = [string]$frame[0]
        $ind    = [int]$frame[1]
        $pad    = "  " * $ind

        if ($key.StartsWith("__CLOSE__:")) {
            $writer.WriteLine($pad + "  ]")
            $writer.WriteLine($pad + "},")
            continue
        }

        if ($opened.Contains($key)) { continue }
        [void]$opened.Add($key)
        $node = $nodeMap[$key]

        $writer.WriteLine($pad + "{")
        $writer.WriteLine($pad + '  "name": "' + (EscJ $node.name) + '",')
        $writer.WriteLine($pad + '  "pid": "' + (EscJ $node.pid) + '",')
        $writer.WriteLine($pad + '  "sha256": "' + (EscJ $node.sha256) + '",')
        $writer.WriteLine($pad + '  "creation_time": "' + (EscJ $node.creation_time) + '",')
        $writer.WriteLine($pad + '  "user": "' + (EscJ $node.user) + '",')
        $writer.WriteLine($pad + '  "commandline": "' + (EscJ $node.commandline) + '",')

        foreach ($field in @("files_created","network_connections","dns_queries","sysmon_rules","process_injections")) {
            $arr = $node[$field]
            if ($arr.Count -eq 0) {
                $writer.WriteLine($pad + '  "' + $field + '": [],')
            } else {
                $writer.WriteLine($pad + '  "' + $field + '": [')
                foreach ($arrItem in $arr) {
                    $escaped = EscJ ([string]$arrItem)
                    $line = [string]::Concat($pad, '    "', $escaped, '",')
                    $writer.WriteLine($line)
                }
                $writer.WriteLine($pad + '  ],')
            }
        }

        $writer.WriteLine($pad + '  "children": [')

        $childKeys = @()
        if ($pid_dict.ContainsKey($key)) {
            $childKeys = @($pid_dict[$key] | Where-Object { $nodeMap.ContainsKey($_) })
        }

        if ($childKeys.Count -eq 0) {
            $writer.WriteLine($pad + "  ]")
            $writer.WriteLine($pad + "},")
        } else {
            $stack.Push(@("__CLOSE__:$key", $ind))
            for ($i = $childKeys.Count - 1; $i -ge 0; $i--) {
                $stack.Push(@($childKeys[$i], ($ind + 2)))
            }
        }
    }

    $writer.WriteLine("  ]")
    $writer.WriteLine("}")
    $writer.Flush()
    $writer.Close()
    $writer.Dispose()

    # Strip trailing commas before ] or }
    Write-Host "  Fixing trailing commas..."
    $raw = [System.IO.File]::ReadAllText($ofile)
    $raw = [System.Text.RegularExpressions.Regex]::Replace($raw, ',(\s*[\]\}])', '$1')
    [System.IO.File]::WriteAllText($ofile, $raw, [System.Text.Encoding]::UTF8)

    Write-Host "  Done: $ofile`n"
}

Write-Host "All files processed."
