$evtx_path = Read-Host "Provide the full path to Sysmon EVTX file(s):"
$ignore_parents = Read-Host "Provide comma-separated list of parent process names to EXCLUDE/IGNORE (or press Enter to skip):"
$filter_users = Read-Host "Provide comma-separated list of usernames to filter on (or press Enter to include all users):"
$force_include = Read-Host "Provide comma-separated list of process names to ALWAYS include (fuzzy match, or press Enter to skip):"

# Parse the ignore list
$ignore_list = @()
if (-not [string]::IsNullOrWhiteSpace($ignore_parents)) {
    $ignore_list = $ignore_parents -split ',' | ForEach-Object { $_.Trim().ToUpper() }
    Write-Host "EXCLUDING these parent processes: $($ignore_list -join ', ')"
}

# Parse the user filter list
$user_filter_list = @()
if (-not [string]::IsNullOrWhiteSpace($filter_users)) {
    $user_filter_list = $filter_users -split ',' | ForEach-Object { $_.Trim().ToUpper() }
    Write-Host "Filtering for these users: $($user_filter_list -join ', ')"
    Write-Host "(Parent processes will be included automatically to maintain tree structure)"
}

# Parse the force include list
$force_include_list = @()
if (-not [string]::IsNullOrWhiteSpace($force_include)) {
    $force_include_list = $force_include -split ',' | ForEach-Object { $_.Trim().ToUpper() }
    Write-Host "ALWAYS including processes matching (fuzzy): $($force_include_list -join ', ')"
    Write-Host "(All child processes will also be included)"
}

$files = Get-ChildItem $evtx_path -Recurse -Filter *.evtx
$fcount = $files.Count
$counter = 0

foreach ($file in $files) {
    $counter++
    $fname = $file.FullName
    Write-Host "Working on $counter of $fcount - $fname"
    
    # Dictionaries to store ALL process information
    $all_processes = @{}         # ProcessGuid -> Process info
    $all_parent_map = @{}        # Child ProcessGuid -> Parent ProcessGuid
    $all_children_map = @{}      # Parent ProcessGuid -> array of child ProcessGuids
    $matched_processes = @{}     # ProcessGuid -> Process info (matching user filter)
    $forced_processes = @{}      # ProcessGuid -> Process info (force included)
    
    # Telemetry data by ProcessGuid
    $network_connections = @{}   # ProcessGuid -> array of connections
    $dns_queries = @{}          # ProcessGuid -> array of DNS queries
    $files_created = @{}        # ProcessGuid -> array of files
    $process_injections = @{}   # ProcessGuid -> array of injections
    $sysmon_rules = @{}         # ProcessGuid -> array of rules/techniques
    
    $system_name = $file.BaseName
    
    # Helper function to clean GUID
    function Clean-Guid {
        param($guid)
        if ([string]::IsNullOrWhiteSpace($guid)) { return $null }
        $guid = $guid -replace '}','' -replace '{',''
        $guid = $guid.Trim().ToUpper()
        return "{$guid}"
    }
    
    # Helper function to check if user matches filter
    function Test-UserMatch {
        param($username)
        
        if ($user_filter_list.Count -eq 0) {
            return $true
        }
        
        if ([string]::IsNullOrWhiteSpace($username)) {
            return $false
        }
        
        $username_upper = $username.ToUpper()
        
        foreach ($filter_user in $user_filter_list) {
            if ($username_upper -eq $filter_user) {
                return $true
            }
            
            if ($username_upper -like "*\*") {
                $username_part = ($username_upper -split '\\')[-1]
                if ($username_part -eq $filter_user) {
                    return $true
                }
            }
            
            if ($filter_user -like "*\*") {
                if ($username_upper -eq $filter_user) {
                    return $true
                }
            }
        }
        
        return $false
    }
    
    # Helper function to check if process name should be ignored
    function Test-ShouldIgnore {
        param($process_name)
        
        if ($ignore_list.Count -eq 0) {
            return $false
        }
        
        if ([string]::IsNullOrWhiteSpace($process_name)) {
            return $false
        }
        
        $process_name_upper = $process_name.ToUpper()
        
        foreach ($ignore_name in $ignore_list) {
            if ($process_name_upper -eq $ignore_name) {
                return $true
            }
        }
        
        return $false
    }
    
    # Helper function to check if process should be force included
    function Test-ForceInclude {
        param($process_name)
        
        if ($force_include_list.Count -eq 0) {
            return $false
        }
        
        if ([string]::IsNullOrWhiteSpace($process_name)) {
            return $false
        }
        
        $process_name_upper = $process_name.ToUpper()
        
        foreach ($force_pattern in $force_include_list) {
            if ($process_name_upper -like "*$force_pattern*") {
                return $true
            }
        }
        
        return $false
    }
    
    # Read EVTX file
    Write-Host "Reading EVTX file..."
    $events = Get-WinEvent -Path $file.FullName -ErrorAction SilentlyContinue
    Write-Host "Total events in EVTX: $($events.Count)"
    
    # Debug counters
    $telemetry_stats = @{
        network = 0
        dns = 0
        files = 0
        injections = 0
        rules = 0
    }
    
    # FIRST PASS: Read ALL events and build process tree
    Write-Host "First pass: Parsing Sysmon events..."
    $event_count = 0
    
    foreach ($event in $events) {
        $event_count++
        if ($event_count % 1000 -eq 0) {
            Write-Host "  Processed $event_count events..."
        }
        
        try {
            $eventId = $event.Id
            $eventXml = [xml]$event.ToXml()
            $eventData = @{}
            
            # Parse EventData
            foreach ($data in $eventXml.Event.EventData.Data) {
                $eventData[$data.Name] = $data.'#text'
            }
            
            # Event ID 1: Process Creation
            if ($eventId -eq 1) {
                $processGuid = Clean-Guid $eventData['ProcessGuid']
                $parentProcessGuid = Clean-Guid $eventData['ParentProcessGuid']
                
                if ([string]::IsNullOrWhiteSpace($processGuid)) { continue }
                
                $image = $eventData['Image']
                $processName = if ($image) { (Split-Path $image -Leaf) } else { "Unknown" }
                $user = $eventData['User']
                $commandLine = $eventData['CommandLine']
                $processPid = $eventData['ProcessId']
                $hashes = $eventData['Hashes']
                
                # Parse hashes
                $sha256 = "Unknown"
                $md5 = "Unknown"
                $sha1 = "Unknown"
                $imphash = "Unknown"
                
                if ($hashes) {
                    $hashArray = $hashes -split ','
                    foreach ($hash in $hashArray) {
                        if ($hash -like "SHA256=*") {
                            $sha256 = ($hash -replace "SHA256=","").Trim()
                        }
                        if ($hash -like "MD5=*") {
                            $md5 = ($hash -replace "MD5=","").Trim()
                        }
                        if ($hash -like "SHA1=*") {
                            $sha1 = ($hash -replace "SHA1=","").Trim()
                        }
                        if ($hash -like "IMPHASH=*") {
                            $imphash = ($hash -replace "IMPHASH=","").Trim()
                        }
                    }
                }
                
                # Store process info
                if (-not $all_processes.ContainsKey($processGuid)) {
                    $all_processes[$processGuid] = @{
                        name = $processName
                        r7_id = $processGuid
                        pid = $processPid
                        sha256 = $sha256
                        md5 = $md5
                        sha1 = $sha1
                        imphash = $imphash
                        creation_time = $event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        user = if ($user) { $user } else { "Unknown" }
                        commandline = if ($commandLine) { $commandLine } else { "Unknown" }
                        exe_path = if ($image) { $image } else { "Unknown" }
                        working_dir = if ($eventData['CurrentDirectory']) { $eventData['CurrentDirectory'] } else { "Unknown" }
                        session = $null
                        file_info = @{
                            owner = "Unknown"
                            description = if ($eventData['Description']) { $eventData['Description'] } else { "Unknown" }
                            product_name = if ($eventData['Product']) { $eventData['Product'] } else { "Unknown" }
                            version = if ($eventData['FileVersion']) { $eventData['FileVersion'] } else { "Unknown" }
                            orig_filename = if ($eventData['OriginalFileName']) { $eventData['OriginalFileName'] } else { "Unknown" }
                            internal_name = "Unknown"
                            signing_status = "Unknown"
                            size = 0
                            created = "Unknown"
                            last_modified = "Unknown"
                        }
                        hash_reputation = @{
                            reputation = "Unknown"
                            threat_level = "Unknown"
                            reliability = "Unknown"
                            engine_count = 0
                            engine_match = 0
                            engine_percent = 0
                            first_analyzed_time = "Unknown"
                        }
                        hostname = $event.MachineName
                        dns_domain = "Unknown"
                        os_type = "Windows"
                        matches_user_filter = (Test-UserMatch $user)
                    }
                }
                
                # Track user filter match
                if (Test-UserMatch $user) {
                    $matched_processes[$processGuid] = $true
                }
                
                # Track force include
                if (Test-ForceInclude $processName) {
                    $forced_processes[$processGuid] = $true
                    Write-Host "  Force included: $processName (GUID: $processGuid)"
                }
                
                # Store parent relationship
                if (-not [string]::IsNullOrWhiteSpace($parentProcessGuid)) {
                    if ($parentProcessGuid -ne "{00000000-0000-0000-0000-000000000000}") {
                        $all_parent_map[$processGuid] = $parentProcessGuid
                        
                        # Build children map
                        if (-not $all_children_map.ContainsKey($parentProcessGuid)) {
                            $all_children_map[$parentProcessGuid] = @()
                        }
                        if ($all_children_map[$parentProcessGuid] -notcontains $processGuid) {
                            $all_children_map[$parentProcessGuid] += $processGuid
                        }
                    }
                }
                
                # Sysmon Rules
                $ruleName = $eventData['RuleName']
                if (-not [string]::IsNullOrWhiteSpace($ruleName)) {
                    if (-not $sysmon_rules.ContainsKey($processGuid)) {
                        $sysmon_rules[$processGuid] = @()
                    }
                    
                    $rules = $ruleName -split ','
                    foreach ($rule in $rules) {
                        $rule = $rule.Trim()
                        if ($rule -and $sysmon_rules[$processGuid] -notcontains $rule) {
                            $sysmon_rules[$processGuid] += $rule
                            $telemetry_stats.rules++
                        }
                    }
                }
            }
            
            # Event ID 3: Network Connection
            elseif ($eventId -eq 3) {
                $processGuid = Clean-Guid $eventData['ProcessGuid']
                if ([string]::IsNullOrWhiteSpace($processGuid)) { continue }
                
                $destIp = $eventData['DestinationIp']
                $destPort = $eventData['DestinationPort']
                $destHostname = $eventData['DestinationHostname']
                $protocol = $eventData['Protocol']
                
                if (-not [string]::IsNullOrWhiteSpace($destIp)) {
                    if (-not $network_connections.ContainsKey($processGuid)) {
                        $network_connections[$processGuid] = @()
                    }
                    
                    $conn_string = "${destIp}:${destPort}"
                    if ($destHostname) { $conn_string += " ($destHostname)" }
                    if ($protocol) { $conn_string += " [$protocol]" }
                    
                    if ($network_connections[$processGuid] -notcontains $conn_string) {
                        $network_connections[$processGuid] += $conn_string
                        $telemetry_stats.network++
                    }
                }
            }
            
            # Event ID 11: File Create
            elseif ($eventId -eq 11) {
                $processGuid = Clean-Guid $eventData['ProcessGuid']
                if ([string]::IsNullOrWhiteSpace($processGuid)) { continue }
                
                $targetFilename = $eventData['TargetFilename']
                if (-not [string]::IsNullOrWhiteSpace($targetFilename)) {
                    if (-not $files_created.ContainsKey($processGuid)) {
                        $files_created[$processGuid] = @()
                    }
                    if ($files_created[$processGuid] -notcontains $targetFilename) {
                        $files_created[$processGuid] += $targetFilename
                        $telemetry_stats.files++
                    }
                }
            }
            
            # Event ID 22: DNS Query
            elseif ($eventId -eq 22) {
                $processGuid = Clean-Guid $eventData['ProcessGuid']
                if ([string]::IsNullOrWhiteSpace($processGuid)) { continue }
                
                $queryName = $eventData['QueryName']
                if (-not [string]::IsNullOrWhiteSpace($queryName)) {
                    if (-not $dns_queries.ContainsKey($processGuid)) {
                        $dns_queries[$processGuid] = @()
                    }
                    if ($dns_queries[$processGuid] -notcontains $queryName) {
                        $dns_queries[$processGuid] += $queryName
                        $telemetry_stats.dns++
                    }
                }
            }
            
            # Event ID 8: CreateRemoteThread
            elseif ($eventId -eq 8) {
                $sourceProcessGuid = Clean-Guid $eventData['SourceProcessGuid']
                $targetImage = $eventData['TargetImage']
                
                if (-not [string]::IsNullOrWhiteSpace($sourceProcessGuid) -and -not [string]::IsNullOrWhiteSpace($targetImage)) {
                    if (-not $process_injections.ContainsKey($sourceProcessGuid)) {
                        $process_injections[$sourceProcessGuid] = @()
                    }
                    
                    $injection_string = "→ $targetImage"
                    if ($process_injections[$sourceProcessGuid] -notcontains $injection_string) {
                        $process_injections[$sourceProcessGuid] += $injection_string
                        $telemetry_stats.injections++
                    }
                }
            }
            
            # Event ID 10: ProcessAccess
            elseif ($eventId -eq 10) {
                $sourceProcessGuid = Clean-Guid $eventData['SourceProcessGuid']
                $targetImage = $eventData['TargetImage']
                $grantedAccess = $eventData['GrantedAccess']
                
                if (-not [string]::IsNullOrWhiteSpace($sourceProcessGuid) -and -not [string]::IsNullOrWhiteSpace($targetImage)) {
                    if (-not $process_injections.ContainsKey($sourceProcessGuid)) {
                        $process_injections[$sourceProcessGuid] = @()
                    }
                    
                    $injection_string = "→ $targetImage (Access: $grantedAccess)"
                    if ($process_injections[$sourceProcessGuid] -notcontains $injection_string) {
                        $process_injections[$sourceProcessGuid] += $injection_string
                        $telemetry_stats.injections++
                    }
                }
            }
            
        } catch {
            Write-Warning "Error parsing event $event_count (ID $eventId): $_"
        }
    }
    
    Write-Host "`nTelemetry captured:"
    Write-Host "  Network connections: $($telemetry_stats.network)"
    Write-Host "  DNS queries: $($telemetry_stats.dns)"
    Write-Host "  Files created: $($telemetry_stats.files)"
    Write-Host "  Process injections: $($telemetry_stats.injections)"
    Write-Host "  Sysmon rules: $($telemetry_stats.rules)"
    
    # Recursive function to include all descendants
    function Include-AllDescendants {
        param($parent_guid, $include_dict)
        
        if ($all_children_map.ContainsKey($parent_guid)) {
            foreach ($child_guid in $all_children_map[$parent_guid]) {
                if (-not $include_dict.ContainsKey($child_guid)) {
                    $include_dict[$child_guid] = $true
                }
                Include-AllDescendants $child_guid $include_dict
            }
        }
    }
    
    # Include all descendants of forced processes
    Write-Host "Including all child processes of force-included processes..."
    $descendant_count_before = $forced_processes.Count
    foreach ($guid in @($forced_processes.Keys)) {
        Include-AllDescendants $guid $forced_processes
    }
    $descendant_count = $forced_processes.Count - $descendant_count_before
    Write-Host "  Added $descendant_count descendant processes"
    
    Write-Host "Total unique processes: $($all_processes.Count)"
    Write-Host "Processes matching user filter: $($matched_processes.Count)"
    Write-Host "Processes force included (with descendants): $($forced_processes.Count)"
    
    # SECOND PASS: Walk up parent chains and include all ancestors
    Write-Host "Second pass: Including parent chains..."
    $processes_to_include = @{}
    
    foreach ($guid in $matched_processes.Keys) {
        $processes_to_include[$guid] = $true
    }
    
    foreach ($guid in $forced_processes.Keys) {
        $processes_to_include[$guid] = $true
    }
    
    $guids_to_process = @($processes_to_include.Keys)
    foreach ($guid in $guids_to_process) {
        $current_guid = $guid
        while ($all_parent_map.ContainsKey($current_guid)) {
            $parent_guid = $all_parent_map[$current_guid]
            
            if (-not $all_processes.ContainsKey($parent_guid)) {
                break
            }
            
            $parent_name = $all_processes[$parent_guid].name
            if (Test-ShouldIgnore $parent_name) {
                break
            }
            
            $processes_to_include[$parent_guid] = $true
            $current_guid = $parent_guid
        }
    }
    
    Write-Host "Total processes to include (with parent chains): $($processes_to_include.Count)"
    
    # THIRD PASS: Build parent map for included processes
    Write-Host "Third pass: Building final parent relationships..."
    $parent_map = @{}
    foreach ($child_guid in $all_parent_map.Keys) {
        if ($processes_to_include.ContainsKey($child_guid)) {
            $parent_guid = $all_parent_map[$child_guid]
            
            if ($processes_to_include.ContainsKey($parent_guid)) {
                $parent_map[$child_guid] = $parent_guid
            }
        }
    }
    
    Write-Host "Total parent relationships in final tree: $($parent_map.Count)"
    
    # Build the process tree recursively
    function Build-ProcessTree {
        param($guid, $visited)
        
        if ($visited.ContainsKey($guid)) {
            Write-Warning "Circular reference detected for GUID $guid"
            return $null
        }
        
        if (-not $processes_to_include.ContainsKey($guid)) {
            return $null
        }
        
        if (-not $all_processes.ContainsKey($guid)) {
            Write-Warning "GUID $guid not found in process list"
            return $null
        }
        
        $visited[$guid] = $true
        $proc = $all_processes[$guid]
        
        $children = @()
        foreach ($child_guid in $parent_map.Keys) {
            if ($parent_map[$child_guid] -eq $guid) {
                $child_proc = Build-ProcessTree $child_guid $visited
                if ($child_proc) {
                    $children += $child_proc
                }
            }
        }
        
        # Get telemetry for this process - ENSURE ARRAYS ARE NEVER NULL
        $proc_files = @()
        if ($files_created.ContainsKey($guid)) {
            $proc_files = $files_created[$guid]
        }
        
        $proc_network = @()
        if ($network_connections.ContainsKey($guid)) {
            $proc_network = $network_connections[$guid]
        }
        
        $proc_dns = @()
        if ($dns_queries.ContainsKey($guid)) {
            $proc_dns = $dns_queries[$guid]
        }
        
        $proc_injections = @()
        if ($process_injections.ContainsKey($guid)) {
            $proc_injections = $process_injections[$guid]
        }
        
        $proc_rules = @()
        if ($sysmon_rules.ContainsKey($guid)) {
            $proc_rules = $sysmon_rules[$guid]
        }
        
        $output = [PSCustomObject]@{
            name = $proc.name
            pid = $proc.r7_id
            actual_pid = $proc.pid
            sha256 = $proc.sha256
            md5 = $proc.md5
            sha1 = $proc.sha1
            imphash = $proc.imphash
            creation_time = $proc.creation_time
            user = $proc.user
            commandline = $proc.commandline
            exe_path = $proc.exe_path
            working_dir = $proc.working_dir
            session = $proc.session
            files_created = $proc_files
            network_connections = $proc_network
            dns_queries = $proc_dns
            sysmon_rules = $proc_rules
            process_injections = $proc_injections
            file_info = $proc.file_info
            hash_reputation = $proc.hash_reputation
            hostname = $proc.hostname
            dns_domain = $proc.dns_domain
            os_type = $proc.os_type
            children = $children
        }
        
        return $output
    }
    
    # Find top-level processes
    $top_level = @()
    foreach ($guid in $processes_to_include.Keys) {
        if (-not $parent_map.ContainsKey($guid)) {
            $top_level += $guid
        }
    }
    
    $top_level = $top_level | Sort-Object -Unique
    
    Write-Host "Top-level processes found: $($top_level.Count)"
    
    # Build root object
    $json = [PSCustomObject]@{
        name = "root"
        pid = 0
        sha256 = @()
        user = "SYSTEM"
        commandline = "ROOT PROCESS TREE"
        files_created = @()
        network_connections = @()
        dns_queries = @()
        sysmon_rules = @()
        process_injections = @()
        children = @()
    }
    
    foreach ($guid in $top_level) {
        $visited = @{}
        $proc_tree = Build-ProcessTree $guid $visited
        if ($proc_tree) {
            $json.children += $proc_tree
        }
    }
    
    # Output to file
    $output_dir = Split-Path $file.FullName
    $ofile = Join-Path $output_dir "$system_name-sysmon.json"
    Write-Host "## Writing output to $ofile"
    Write-Host "Total top-level processes in output: $($json.children.Count)"
    
    function Count-Processes {
        param($node)
        $count = 1
        if ($node.children) {
            foreach ($child in $node.children) {
                $count += Count-Processes $child
            }
        }
        return $count
    }
    
    $total_in_tree = 0
    foreach ($child in $json.children) {
        $total_in_tree += Count-Processes $child
    }
    Write-Host "Total processes in tree: $total_in_tree"
    
    $json | ConvertTo-Json -Depth 100 | Out-File $ofile
    
    Write-Host "`nDone! Check the JSON file and load it into the HTML viewer."
}
