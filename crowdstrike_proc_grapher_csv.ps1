# ============================================================
#  Convert-DefenderATPtoProcessTree.ps1
# ============================================================

$file_path = Read-Host "Provide the full path to the folder containing Defender ATP CSV export file(s)"
$files = Get-ChildItem $file_path -Recurse -Filter *.csv
$fcount = $files.Count
$counter = 0

function Make-ProcessKey {
    param([string]$MachineId, [string]$ProcessId, [string]$CreationTime, [string]$FileName)
    if ([string]::IsNullOrWhiteSpace($ProcessId) -or $ProcessId -eq "0") { return $null }
    if ([string]::IsNullOrWhiteSpace($FileName)) { return $null }
    # Only treat as a process if the filename looks like an executable
    if ($FileName -notmatch '\.(exe|dll|com|bat|cmd|ps1|vbs|js|scr|pif|msi|msc|hta|cpl)$') { return $null }
    $ts = ""
    if (-not [string]::IsNullOrWhiteSpace($CreationTime)) {
        try   { $ts = [datetime]::Parse($CreationTime).ToString("yyyyMMddHHmmssfff") }
        catch { $ts = ($CreationTime -replace "[^0-9]",""); if ($ts.Length -gt 17) { $ts = $ts.Substring(0,17) } }
    }
    # Key includes filename so same PID reused by different processes stays separate
    $safeName = $FileName.ToUpper().Trim()
    return ($MachineId + "_" + $ProcessId + "_" + $ts + "_" + $safeName).ToUpper()
}

function Add-Unique {
    param($dict, [string]$key, [string]$value)
    if ([string]::IsNullOrWhiteSpace($key))   { return }
    if ([string]::IsNullOrWhiteSpace($value)) { return }
    if (-not $dict.ContainsKey($key)) { $dict[$key] = [System.Collections.Generic.HashSet[string]]::new() }
    [void]$dict[$key].Add($value)
}

function Set-IfMissing {
    param($dict,[string]$key,[string]$value)
    if (-not [string]::IsNullOrWhiteSpace($key) -and -not $dict.ContainsKey($key)) { $dict[$key] = $value }
}

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

$NetworkActionTypes = [System.Collections.Generic.HashSet[string]]@("NetworkConnectionInspected","ConnectionSuccess","ConnectionFailed","ConnectionFound","InboundConnectionAccepted","ListeningConnectionCreated")
$DnsActionTypes     = [System.Collections.Generic.HashSet[string]]@("DnsQueryResponse","DnsQueryRequest","DnsQuery")
$FileActionTypes    = [System.Collections.Generic.HashSet[string]]@("FileCreated","FileModified","FileRenamed")

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
    $xprocess_dict = @{}

    $system_name = ($file.Name -replace "\.csv$", "")

    Write-Host "  Reading CSV..."
    $rows = Import-Csv -Path $file.FullName
    Write-Host "  Processing $($rows.Count) rows..."

    foreach ($row in $rows) {
        $machineId  = $row."Machine Id"
        $actionType = $row."Action Type".Trim()

        if ($actionType -ne "ProcessCreated") {
            # Non-creation event: only attach activity to the initiating process
            # Never create new nodes from these rows
            $initProcId     = $row."Initiating Process Id"
            $initProcTime   = $row."Initiating Process Creation Time"
            $initProcName   = if ($row."Initiating Process File Name") { $row."Initiating Process File Name".ToUpper().Trim() } else { "" }
            $initKey = Make-ProcessKey -MachineId $machineId -ProcessId $initProcId -CreationTime $initProcTime -FileName $initProcName
        } else {
            # ProcessCreated: build the full tree - child, initiating parent, grandparent
            $initProcId     = $row."Initiating Process Id"
            $initProcTime   = $row."Initiating Process Creation Time"
            $initProcName   = if ($row."Initiating Process File Name")    { $row."Initiating Process File Name".ToUpper().Trim() }    else { "" }
            $initProcCLI    = if ($row."Initiating Process Command Line") { $row."Initiating Process Command Line".ToUpper().Trim() } else { "" }
            $initProcSha256 = if ($row."Initiating Process SHA256")       { $row."Initiating Process SHA256".ToUpper().Trim() }       else { "" }
            $initProcUser   = ($row."Initiating Process Account Domain" + [string][char]92 + $row."Initiating Process Account Name").ToUpper().Trim().TrimStart([string][char]92)

            $gpProcId   = $row."Initiating Process Parent Id"
            $gpProcTime = $row."Initiating Process Parent Creation Time"
            $gpProcName = if ($row."Initiating Process Parent File Name") { $row."Initiating Process Parent File Name".ToUpper().Trim() } else { "" }

            $childProcId     = $row."Process Id"
            $childProcTime   = $row."Process Creation Time"
            $childProcName   = if ($row."File Name")            { $row."File Name".ToUpper().Trim() }            else { "" }
            $childProcCLI    = if ($row."Process Command Line") { $row."Process Command Line".ToUpper().Trim() } else { "" }
            $childProcSha256 = if ($row."Sha256")               { $row."Sha256".ToUpper().Trim() }               else { "" }
            $childProcUser   = ($row."Account Domain" + [string][char]92 + $row."Account Name").ToUpper().Trim().TrimStart([string][char]92)

            $initKey  = Make-ProcessKey -MachineId $machineId -ProcessId $initProcId  -CreationTime $initProcTime  -FileName $initProcName
            $gpKey    = Make-ProcessKey -MachineId $machineId -ProcessId $gpProcId    -CreationTime $gpProcTime    -FileName $gpProcName
            $childKey = Make-ProcessKey -MachineId $machineId -ProcessId $childProcId -CreationTime $childProcTime -FileName $childProcName

            Set-IfMissing $pid_time $initKey  $initProcTime
            Set-IfMissing $pid_time $gpKey    $gpProcTime
            Set-IfMissing $pid_time $childKey $childProcTime

            if ($initProcName  -ne "" -and $initKey)  { Add-Unique $pname_dict $initKey  $initProcName }
            if ($gpProcName    -ne "" -and $gpKey)     { Add-Unique $pname_dict $gpKey    $gpProcName }
            if ($childProcName -ne "" -and $childKey)  { Add-Unique $pname_dict $childKey $childProcName }

            if ($initProcCLI  -ne "" -and $initKey)  { Add-Unique $cli_dict $initKey  $initProcCLI }
            if ($childProcCLI -ne "" -and $childKey) { Add-Unique $cli_dict $childKey $childProcCLI }

            if ($initProcSha256  -ne "" -and $initKey  -and -not $hashes_dict.ContainsKey($initKey))  { $hashes_dict[$initKey]  = $initProcSha256 }
            if ($childProcSha256 -ne "" -and $childKey -and -not $hashes_dict.ContainsKey($childKey)) { $hashes_dict[$childKey] = $childProcSha256 }

            if ($initProcUser  -notin @("","\") -and $initKey)  { Add-Unique $pid_user_dict $initKey  $initProcUser }
            if ($childProcUser -notin @("","\") -and $childKey) { Add-Unique $pid_user_dict $childKey $childProcUser }

            # Tree edges
            if ($gpKey   -and $initKey  -and $gpKey   -ne $initKey)  { Add-Unique $pid_dict $gpKey   $initKey }
            if ($initKey -and $childKey -and $initKey -ne $childKey) { Add-Unique $pid_dict $initKey $childKey }

            # Action type on initiating process
            if ($initKey) { Add-Unique $rules_dict $initKey $actionType }
        }

        # Attach activity to initiating process for ALL event types
        if ($initKey) { Add-Unique $rules_dict $initKey $actionType }

        if ($NetworkActionTypes.Contains($actionType)) {
            $remoteIp = $row."Remote IP"; $remotePort = $row."Remote Port"
            if (-not [string]::IsNullOrWhiteSpace($remoteIp)) {
                $remote = ($remoteIp + ":" + $remotePort).Trim(":")
                if ($initKey) { Add-Unique $pid_connect $initKey $remote }
            }
        }
        if ($DnsActionTypes.Contains($actionType)) {
            $remoteUrl = $row."Remote Url"
            if (-not [string]::IsNullOrWhiteSpace($remoteUrl)) {
                if ($initKey) { Add-Unique $pid_dns $initKey $remoteUrl.ToUpper().Trim() }
            }
        }
        if ($FileActionTypes.Contains($actionType)) {
            $folder = [string]($row.'Folder Path')
            $fname2 = [string]($row.'File Name')
            $fpath  = ""
            if ($folder.Length -gt 1 -and $fname2.Length -gt 0) {
                $fpath = ($folder.TrimEnd([char]92) + [string][char]92 + $fname2).ToUpper()
            } elseif ($fname2.Length -gt 1) {
                $fpath = $fname2.ToUpper()
            }
            if ($fpath.Length -gt 1) { Add-Unique $pid_create $initKey $fpath }
        }
        $fou = $row."File Origin Url"
        if (-not [string]::IsNullOrWhiteSpace($fou) -and $initKey) { Add-Unique $pid_dns $initKey $fou.ToUpper().Trim() }
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
        $pname = if ($pname_dict[$key] -and $pname_dict[$key].Count -gt 0) { @($pname_dict[$key]) -join ", " } else { "Unknown" }
        $puser = if ($pid_user_dict[$key] -and $pid_user_dict[$key].Count -gt 0) { @($pid_user_dict[$key]) -join ", " } else { "Unknown" }
        $phash = if ($hashes_dict[$key]) { $hashes_dict[$key] } else { "Unknown" }
        $cli   = if ($cli_dict[$key] -and $cli_dict[$key].Count -gt 0) { @($cli_dict[$key]) -join " | " } else { "Unknown" }
        $ptime = if ($pid_time[$key]) { $pid_time[$key] } else { "Unknown" }
        $files       = if ($pid_create[$key]  -and $pid_create[$key].Count  -gt 0) { @($pid_create[$key])  } else { @() }
        $connections = if ($pid_connect[$key] -and $pid_connect[$key].Count -gt 0) { @($pid_connect[$key]) } else { @() }
        $queries     = if ($pid_dns[$key]     -and $pid_dns[$key].Count     -gt 0) { @($pid_dns[$key])     } else { @() }
        $rules       = if ($rules_dict[$key]  -and $rules_dict[$key].Count  -gt 0) { @($rules_dict[$key])  } else { @() }
        $injections  = @()

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
            process_injections  = $injections
        }
    }

    # Exclusion prompt
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

    # Write JSON directly via StreamWriter - no serialiser, no function calls in hot path
    $ofile  = Join-Path $file_path ($system_name + "_processtree.json")
    Write-Host "  Writing $ofile ..."
    if (Test-Path $ofile) { Remove-Item $ofile -Force }
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

    # Iterative DFS write.
    # Stack holds [key, indent]. Always writes commas; trailing commas stripped after.
    # $opened tracks keys whose opening brace has already been written,
    # so when we see a key a second time we know to close it.
    $stack  = [System.Collections.Generic.Stack[object[]]]::new()
    $opened = [System.Collections.Generic.HashSet[string]]::new()

    # Push root children - NO isLast tracking, always write commas, strip at end
    for ($i = $validRootKeys.Count - 1; $i -ge 0; $i--) {
        $stack.Push(@($validRootKeys[$i], 2))
    }

    while ($stack.Count -gt 0) {
        $frame = $stack.Pop()
        $key   = [string]$frame[0]
        $ind   = [int]$frame[1]
        $pad   = "  " * $ind

        # Handle close sentinel
        if ($key.StartsWith("__CLOSE__:")) {
            $writer.WriteLine($pad + "  ]")
            $writer.WriteLine($pad + "},")
            continue
        }

        if ($opened.Contains($key)) {
            # Already written elsewhere in tree - skip entirely, write nothing
            continue
        }

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
            # Push a CLOSE marker - use a special sentinel key, not the real key
            $stack.Push(@("__CLOSE__:$key", $ind))
            # Push children in reverse so first child pops first
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

    # Strip trailing commas before ] or } - fixes all comma issues in one pass
    Write-Host "  Fixing trailing commas..."
    $raw = [System.IO.File]::ReadAllText($ofile)
    $raw = [System.Text.RegularExpressions.Regex]::Replace($raw, ',(\s*[\]\}])', '$1')
    [System.IO.File]::WriteAllText($ofile, $raw, [System.Text.Encoding]::UTF8)

    Write-Host "  Done: $ofile`n"
}

Write-Host "All files processed."
