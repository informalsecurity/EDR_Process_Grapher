# ============================================================
#  Convert-CrowdStrikeToProcessTree.ps1
#  Converts CrowdStrike Falcon Advanced Event Search (Humio)
#  CSV exports into process-tree JSON files consumable by
#  the Process Tree Viewer HTML tool.
# ============================================================

$input_path = Read-Host "Provide the full path to a CrowdStrike CSV file OR a folder containing them"
$input_path = $input_path.Trim().Trim('"').Trim("'")

# Accept either a single file or a folder
if (Test-Path $input_path -PathType Leaf) {
    $files = @(Get-Item $input_path)
    $file_path = Split-Path $input_path -Parent
} elseif (Test-Path $input_path -PathType Container) {
    $files = @(Get-ChildItem $input_path -Recurse -Filter *.csv)
    $file_path = $input_path
} else {
    Write-Host "ERROR: path not found: $input_path"
    exit
}

$fcount = $files.Count
$counter = 0
Write-Host "Found $fcount file(s) to process."

# Auto-detect delimiter by sampling the header line of the first file
$delimiter = ","
if ($fcount -gt 0) {
    $headerLine = Get-Content $files[0].FullName -TotalCount 1
    $tabCount   = ($headerLine.ToCharArray() | Where-Object { $_ -eq [char]9 }).Count
    $commaCount = ($headerLine.ToCharArray() | Where-Object { $_ -eq ',' }).Count
    if ($tabCount -gt $commaCount) {
        $delimiter = "`t"
        Write-Host "Detected TAB-delimited CSV."
    } else {
        Write-Host "Detected COMMA-delimited CSV."
    }
}

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

    Write-Host "  Streaming CSV (row by row to save memory)..."
    $rowNum = 0

    Import-Csv -Path $file.FullName -Delimiter $delimiter | ForEach-Object {
        $row = $_
        $rowNum++
        if ($rowNum % 5000 -eq 0) { Write-Host "    ...processed $rowNum rows" }

        # CrowdStrike flat CSV columns are unreliable/empty across export types.
        # The @rawstring column always contains the full event JSON - parse that.
        $raw = [string]$row."@rawstring"
        if ([string]::IsNullOrWhiteSpace($raw)) { return }   # 'return' = next item in ForEach-Object

        try {
            $ev = $raw | ConvertFrom-Json
        } catch {
            return
        }

        $aid       = [string]$ev.aid
        $eventName = [string]$ev.event_simpleName
        if ($null -eq $eventName) { $eventName = "" }
        $eventName = $eventName.Trim()

        if ($ProcessEvents.Contains($eventName)) {
            # ── Process creation ──────────────────────────────────
            $targetId = [string]$ev.TargetProcessId
            $sourceId = [string]$ev.SourceProcessId
            if ([string]::IsNullOrWhiteSpace($sourceId)) { $sourceId = [string]$ev.ParentProcessId }

            $childKey  = Make-ProcessKey -Aid $aid -ProcessId $targetId
            $parentKey = Make-ProcessKey -Aid $aid -ProcessId $sourceId

            $procName   = Get-BaseName ([string]$ev.ImageFileName)
            $parentName = if ($ev.ParentBaseFileName) { ([string]$ev.ParentBaseFileName).ToUpper().Trim() } else { "" }
            $cli        = if ($ev.CommandLine)        { ([string]$ev.CommandLine).ToUpper().Trim() }        else { "" }
            $sha256     = if ($ev.SHA256HashData)     { ([string]$ev.SHA256HashData).ToUpper().Trim() }     else { "" }
            $userName   = if ($ev.UserName)           { ([string]$ev.UserName).ToUpper().Trim() }           else { "" }
            $isoTime    = Convert-CSTimestamp ([string]$ev.ProcessStartTime)

            $tactic     = if ($ev.Tactic)      { ([string]$ev.Tactic).Trim() }      else { "" }
            $technique  = if ($ev.Technique)   { ([string]$ev.Technique).Trim() }   else { "" }
            $techId     = if ($ev.TechniqueId) { ([string]$ev.TechniqueId).Trim() } else { "" }

            if ($childKey) {
                Set-IfMissing $pid_time $childKey $isoTime
                if ($procName -ne "") { Add-Unique $pname_dict    $childKey $procName }
                if ($cli      -ne "") { Add-Unique $cli_dict      $childKey $cli }
                if ($userName -ne "") { Add-Unique $pid_user_dict $childKey $userName }
                if ($sha256   -ne "" -and -not $hashes_dict.ContainsKey($childKey)) { $hashes_dict[$childKey] = $sha256 }
                if ($eventName -ne "") { Add-Unique $rules_dict $childKey $eventName }
                if ($tactic    -ne "") { Add-Unique $rules_dict $childKey $tactic }
                if ($techId    -ne "") { Add-Unique $rules_dict $childKey ($techId + " - " + $technique) }
            }
            if ($parentKey -and $parentName -ne "") { Add-Unique $pname_dict $parentKey $parentName }
            if ($parentKey -and $childKey -and $parentKey -ne $childKey) {
                Add-Unique $pid_dict $parentKey $childKey
            }

        } else {
            # ── Non-process event: attach activity to actor (ContextProcessId) ──
            $ctxId    = [string]$ev.ContextProcessId
            $actorKey = Make-ProcessKey -Aid $aid -ProcessId $ctxId
            if (-not $actorKey) { return }   # 'return' = next item

            $ctxName = [string]$ev.ContextBaseFileName
            if (-not [string]::IsNullOrWhiteSpace($ctxName)) {
                Add-Unique $pname_dict $actorKey $ctxName.ToUpper().Trim()
            }

            if ($eventName -ne "") { Add-Unique $rules_dict $actorKey $eventName }

            $tactic = if ($ev.Tactic)      { ([string]$ev.Tactic).Trim() }      else { "" }
            $techId = if ($ev.TechniqueId) { ([string]$ev.TechniqueId).Trim() } else { "" }
            $tech   = if ($ev.Technique)   { ([string]$ev.Technique).Trim() }   else { "" }
            if ($tactic -ne "") { Add-Unique $rules_dict $actorKey $tactic }
            if ($techId -ne "") { Add-Unique $rules_dict $actorKey ($techId + " - " + $tech) }

            # Network
            if (Is-NetworkEvent $eventName) {
                $remoteIp = [string]$ev.RemoteAddressIP4
                if ([string]::IsNullOrWhiteSpace($remoteIp)) { $remoteIp = [string]$ev.RemoteAddressString }
                $remotePort = [string]$ev.RemotePort
                if (-not [string]::IsNullOrWhiteSpace($remoteIp) -and $remoteIp -ne "0.0.0.0") {
                    $remote = ($remoteIp + ":" + $remotePort).Trim(":")
                    Add-Unique $pid_connect $actorKey $remote
                }
            }

            # DNS
            if ($eventName -eq "DnsRequest") {
                $domain = [string]$ev.DomainName
                if (-not [string]::IsNullOrWhiteSpace($domain)) {
                    Add-Unique $pid_dns $actorKey $domain.ToUpper().Trim()
                }
            }

            # File writes - TargetFileName in the JSON has the full path
            if (Is-FileWriteEvent $eventName) {
                $tfn = [string]$ev.TargetFileName
                if (-not [string]::IsNullOrWhiteSpace($tfn) -and $tfn.Length -gt 1) {
                    Add-Unique $pid_create $actorKey $tfn.ToUpper()
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
    $seen_tl = [System.Collections.Generic.HashSet[string]]::new()
    $tl_unique = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $top_level) { if ($seen_tl.Add($k)) { [void]$tl_unique.Add($k) } }
    $top_level = $tl_unique

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

    # ── Exclusion prompt (by process name, ANYWHERE in the tree) ──
    # Count EVERY process name across ALL nodes (parents and children, any depth)
    $nameCounts = @{}
    foreach ($k in $nodeMap.Keys) {
        $nm = $nodeMap[$k].name
        if ([string]::IsNullOrWhiteSpace($nm)) { continue }
        if ($nameCounts.ContainsKey($nm)) { $nameCounts[$nm]++ } else { $nameCounts[$nm] = 1 }
    }

    # Sort by count descending, take top 20
    $sortedNames = @($nameCounts.GetEnumerator() | Sort-Object -Property Value -Descending)
    $top20 = @($sortedNames | Select-Object -First 20)

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  TOP 20 MOST COMMON PROCESS NAMES for: $system_name"
    Write-Host "  ($($nameCounts.Count) unique process names total)"
    Write-Host "------------------------------------------------------------"
    $i = 1
    foreach ($entry in $top20) {
        Write-Host ("  {0,3}.  {1,-40} {2} occurrence{3}" -f $i, $entry.Key, $entry.Value, $(if ($entry.Value -ne 1){"s"}else{""}))
        $i++
    }
    Write-Host "============================================================"
    Write-Host ""
    Write-Host "  Enter process names to EXCLUDE from the tree (parent OR child, any depth)."
    Write-Host "  You can type the NUMBER from the list above, or the process NAME."
    Write-Host "  Comma-separated. Press ENTER to keep all:"
    $excludeInput = Read-Host "  Exclude"

    $excludeNames = [System.Collections.Generic.HashSet[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($excludeInput)) {
        foreach ($token in ($excludeInput -split ",")) {
            $t = $token.Trim()
            if ($t -eq "") { continue }
            # If it is a number, map to the name from the top 20 list
            $num = 0
            if ([int]::TryParse($t, [ref]$num)) {
                if ($num -ge 1 -and $num -le $top20.Count) {
                    [void]$excludeNames.Add($top20[$num - 1].Key.ToUpper())
                }
            } else {
                [void]$excludeNames.Add($t.ToUpper())
            }
        }
    }

    if ($excludeNames.Count -gt 0) {
        Write-Host "  Excluding these process names everywhere in the tree:"
        foreach ($en in $excludeNames) { Write-Host "    - $en" }

        # Remove excluded nodes from nodeMap entirely
        $removedKeys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($k in @($nodeMap.Keys)) {
            if ($excludeNames.Contains($nodeMap[$k].name.ToUpper())) {
                [void]$removedKeys.Add($k)
                $nodeMap.Remove($k)
            }
        }

        # Remove edges pointing to or from removed keys
        foreach ($pk in @($pid_dict.Keys)) {
            if ($removedKeys.Contains($pk)) { $pid_dict.Remove($pk); continue }
            $kept = [System.Collections.Generic.List[string]]::new()
            foreach ($ck in $pid_dict[$pk]) {
                if (-not $removedKeys.Contains($ck)) { [void]$kept.Add($ck) }
            }
            $pid_dict[$pk] = $kept
        }

        Write-Host "  Removed $($removedKeys.Count) node(s) from the tree."
    } else {
        Write-Host "  No exclusions applied."
    }
    Write-Host ""

    # Recompute top-level roots AFTER exclusions
    $allChildKeys2 = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($key in $pid_dict.Keys) {
        foreach ($child in $pid_dict[$key]) { [void]$allChildKeys2.Add($child) }
    }
    $validRootKeys = [System.Collections.Generic.List[string]]::new()
    $seenRoot = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($k in $pid_dict.Keys) {
        if (-not $allChildKeys2.Contains($k) -and $nodeMap.ContainsKey($k)) {
            if ($seenRoot.Add($k)) { [void]$validRootKeys.Add($k) }
        }
    }
    # Also include any surviving orphan nodes that have activity but no edges
    foreach ($k in $nodeMap.Keys) {
        if (-not $allChildKeys2.Contains($k) -and -not $pid_dict.ContainsKey($k)) {
            if ($seenRoot.Add($k)) { [void]$validRootKeys.Add($k) }
        }
    }
    Write-Host "  $($validRootKeys.Count) top-level process(es) after exclusions."
    Write-Host ""

    # ── Write JSON ────────────────────────────────────────────────
    $ofile = Join-Path $file_path ($system_name + "_processtree.json")
    if (Test-Path $ofile) {
        try { Remove-Item $ofile -Force -ErrorAction Stop }
        catch { Write-Host "  WARNING: could not delete existing file, trying a new name"; $ofile = Join-Path $file_path ($system_name + "_processtree_" + (Get-Date -Format "HHmmss") + ".json") }
    }
    Write-Host "  Writing $ofile ..."
    $writer = $null
    try {
        $writer = [System.IO.StreamWriter]::new($ofile, $false, [System.Text.Encoding]::UTF8)
    } catch {
        Write-Host "  ERROR opening output file: $($_.Exception.Message)"
        Write-Host "  Skipping this file."
        continue
    }
    if ($null -eq $writer) { Write-Host "  ERROR: writer is null, skipping"; continue }

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

        $childKeys = [System.Collections.Generic.List[string]]::new()
        if ($pid_dict.ContainsKey($key)) {
            foreach ($ck in $pid_dict[$key]) {
                if ($nodeMap.ContainsKey($ck)) { [void]$childKeys.Add($ck) }
            }
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
