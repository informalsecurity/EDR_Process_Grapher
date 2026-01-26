$file_path = Read-Host "Provide the full path to Rapid7 CSV file(s):"
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

$files = Get-ChildItem $file_path -Recurse -Filter *.csv
$fcount = $files.Count
$counter = 0

foreach ($file in $files) {
    $counter++
    $fname = $file.FullName
    Write-Host "Working on $counter of $fcount - $fname"
    
    # Dictionaries to store ALL process information (before filtering)
    $all_processes = @{}         # r7_id -> Process info (ALL processes)
    $all_parent_map = @{}        # Child r7_id -> Parent r7_id (ALL relationships)
    $all_children_map = @{}      # Parent r7_id -> array of child r7_ids
    $matched_processes = @{}     # r7_id -> Process info (matching user filter)
    $forced_processes = @{}      # r7_id -> Process info (force included)
    
    # Telemetry data by process r7_id
    $network_connections = @{}   # r7_id -> array of connections
    $dns_queries = @{}          # r7_id -> array of DNS queries
    $files_created = @{}        # r7_id -> array of files
    $process_injections = @{}   # r7_id -> array of injections
    $sysmon_rules = @{}         # r7_id -> array of rules/techniques
    
    $system_name = $file.BaseName
    
    # Read CSV file (suppress duplicate column warnings)
    Write-Host "Reading CSV file..."
    $csv_data = Import-Csv -Path $file.FullName -ErrorAction SilentlyContinue
    
    Write-Host "Total rows in CSV: $($csv_data.Count)"
    
    # Helper function to check if user matches filter
    function Test-UserMatch {
        param($username)
        
        if ($user_filter_list.Count -eq 0) {
            return $true  # No filter, include all
        }
        
        if ([string]::IsNullOrWhiteSpace($username)) {
            return $false
        }
        
        $username_upper = $username.ToUpper()
        
        foreach ($filter_user in $user_filter_list) {
            # Check exact match
            if ($username_upper -eq $filter_user) {
                return $true
            }
            
            # Check if username is DOMAIN\USERNAME format and filter matches USERNAME part
            if ($username_upper -like "*\*") {
                $username_part = ($username_upper -split '\\')[-1]
                if ($username_part -eq $filter_user) {
                    return $true
                }
            }
            
            # Check if filter is DOMAIN\USERNAME format and matches full username
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
            return $false  # No ignore list, don't ignore anything
        }
        
        if ([string]::IsNullOrWhiteSpace($process_name)) {
            return $false
        }
        
        $process_name_upper = $process_name.ToUpper()
        
        foreach ($ignore_name in $ignore_list) {
            if ($process_name_upper -eq $ignore_name) {
                return $true  # This process IS in the ignore list, so ignore it
            }
        }
        
        return $false  # Not in ignore list, keep it
    }
    
    # Helper function to check if process should be force included (fuzzy match)
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
    
    # FIRST PASS: Read ALL processes and events
    Write-Host "First pass: Reading all processes and events..."
    foreach ($row in $csv_data) {
        try {
            $process_r7id = $row.'json.process.r7_id'
            $parent_r7id = $row.'json.parent_process.r7_id'
            $process_pid = $row.'json.process.pid'
            $process_name = $row.'json.process.name'
            $parent_name = $row.'json.parent_process.name'
            $process_user = $row.'json.process.username'
            $event_name = $row.'json.event_name'
            $event_id = $row.'json.event_id'
            
            # Skip if no process r7_id
            if ([string]::IsNullOrWhiteSpace($process_r7id)) {
                continue
            }
            
            # Store ALL processes (regardless of user filter)
            if (-not $all_processes.ContainsKey($process_r7id)) {
                $all_processes[$process_r7id] = @{
                    name = if ($process_name) { $process_name } else { "Unknown" }
                    r7_id = $process_r7id
                    pid = $process_pid
                    sha256 = if ($row.'json.process.exe_file.hashes.sha256') { $row.'json.process.exe_file.hashes.sha256' } else { "Unknown" }
                    md5 = if ($row.'json.process.exe_file.hashes.md5') { $row.'json.process.exe_file.hashes.md5' } else { "Unknown" }
                    sha1 = if ($row.'json.process.exe_file.hashes.sha1') { $row.'json.process.exe_file.hashes.sha1' } else { "Unknown" }
                    imphash = if ($row.'json.process.exe_file.hashes.imphash') { $row.'json.process.exe_file.hashes.imphash' } else { "Unknown" }
                    creation_time = $row.'json.process.start_time'
                    user = $process_user
                    commandline = $row.'json.process.cmd_line'
                    exe_path = $row.'json.process.exe_path'
                    working_dir = $row.'json.process.working_dir'
                    session = $row.'json.process.session'
                    file_info = @{
                        owner = if ($row.'json.process.exe_file.owner') { $row.'json.process.exe_file.owner' } else { "Unknown" }
                        description = if ($row.'json.process.exe_file.description') { $row.'json.process.exe_file.description' } else { "Unknown" }
                        product_name = if ($row.'json.process.exe_file.product_name') { $row.'json.process.exe_file.product_name' } else { "Unknown" }
                        version = if ($row.'json.process.exe_file.version') { $row.'json.process.exe_file.version' } else { "Unknown" }
                        orig_filename = if ($row.'json.process.exe_file.orig_filename') { $row.'json.process.exe_file.orig_filename' } else { "Unknown" }
                        internal_name = if ($row.'json.process.exe_file.internal_name') { $row.'json.process.exe_file.internal_name' } else { "Unknown" }
                        signing_status = if ($row.'json.process.exe_file.signing_status') { $row.'json.process.exe_file.signing_status' } else { "Unknown" }
                        size = if ($row.'json.process.exe_file.size') { $row.'json.process.exe_file.size' } else { 0 }
                        created = $row.'json.process.exe_file.created'
                        last_modified = $row.'json.process.exe_file.last_modified'
                    }
                    hash_reputation = @{
                        reputation = $row.'json.process.hash_reputation.reputation'
                        threat_level = $row.'json.process.hash_reputation.threat_level'
                        reliability = $row.'json.process.hash_reputation.reliability'
                        engine_count = $row.'json.process.hash_reputation.engine_count'
                        engine_match = $row.'json.process.hash_reputation.engine_match'
                        engine_percent = $row.'json.process.hash_reputation.engine_percent'
                        first_analyzed_time = $row.'json.process.hash_reputation.first_analyzed_time'
                    }
                    hostname = $row.'json.hostname'
                    dns_domain = $row.'json.dns_domain'
                    os_type = $row.'json.os_type'
                    matches_user_filter = (Test-UserMatch $process_user)
                }
            }
            
            # Track if this process matches the user filter
            if (Test-UserMatch $process_user) {
                $matched_processes[$process_r7id] = $true
            }
            
            # Store ALL parent relationships and build children map
            if (-not [string]::IsNullOrWhiteSpace($parent_r7id)) {
                # Skip parent relationship ONLY if the parent is {00000000-0000-0000-0000-000000000000}
                if ($parent_r7id -ne "{00000000-0000-0000-0000-000000000000}") {
                    $all_parent_map[$process_r7id] = $parent_r7id
                    
                    # Build children map
                    if (-not $all_children_map.ContainsKey($parent_r7id)) {
                        $all_children_map[$parent_r7id] = @()
                    }
                    if ($all_children_map[$parent_r7id] -notcontains $process_r7id) {
                        $all_children_map[$parent_r7id] += $process_r7id
                    }
                }
            }
            
            # Parse Sysmon events for telemetry
            # Network Connection (Event ID 3)
            if ($event_id -eq "3" -or $event_name -like "*Network*") {
                $dest_ip = $row.'json.event.EventData.Data.DestinationIp'
                $dest_port = $row.'json.event.EventData.Data.DestinationPort'
                $dest_hostname = $row.'json.event.EventData.Data.DestinationHostname'
                $protocol = $row.'json.event.EventData.Data.Protocol'
                $geoip_country = $row.'json.geoip_country_name'
                $geoip_city = $row.'json.geoip_city'
                
                if (-not [string]::IsNullOrWhiteSpace($dest_ip)) {
                    if (-not $network_connections.ContainsKey($process_r7id)) {
                        $network_connections[$process_r7id] = @()
                    }
                    
                    $conn_string = "${dest_ip}:${dest_port}"
                    if ($dest_hostname) { $conn_string += " ($dest_hostname)" }
                    if ($protocol) { $conn_string += " [$protocol]" }
                    if ($geoip_country) { $conn_string += " - $geoip_country" }
                    if ($geoip_city) { $conn_string += ", $geoip_city" }
                    
                    if ($network_connections[$process_r7id] -notcontains $conn_string) {
                        $network_connections[$process_r7id] += $conn_string
                    }
                }
            }
            
            # DNS Query (Event ID 22)
            if ($event_id -eq "22" -or $event_name -like "*DNS*") {
                $query_name = $row.'json.event.EventData.Data.QueryName'
                if (-not [string]::IsNullOrWhiteSpace($query_name)) {
                    if (-not $dns_queries.ContainsKey($process_r7id)) {
                        $dns_queries[$process_r7id] = @()
                    }
                    if ($dns_queries[$process_r7id] -notcontains $query_name) {
                        $dns_queries[$process_r7id] += $query_name
                    }
                }
            }
            
            # File Create (Event ID 11)
            if ($event_id -eq "11" -or $event_name -like "*FileCreate*") {
                $target_filename = $row.'json.event.EventData.Data.TargetFilename'
                if (-not [string]::IsNullOrWhiteSpace($target_filename)) {
                    if (-not $files_created.ContainsKey($process_r7id)) {
                        $files_created[$process_r7id] = @()
                    }
                    if ($files_created[$process_r7id] -notcontains $target_filename) {
                        $files_created[$process_r7id] += $target_filename
                    }
                }
            }
            
            # Process Injection (Event ID 8 - CreateRemoteThread, Event ID 10 - ProcessAccess)
            if ($event_id -eq "8" -or $event_id -eq "10" -or $event_name -like "*RemoteThread*" -or $event_name -like "*ProcessAccess*") {
                $source_image = $row.'json.event.EventData.Data.SourceImage'
                $target_image = $row.'json.event.EventData.Data.TargetImage'
                $source_guid = $row.'json.event.EventData.Data.SourceProcessGuid'
                $target_guid = $row.'json.event.EventData.Data.TargetProcessGuid'
                $granted_access = $row.'json.event.EventData.Data.GrantedAccess'
                
                if (-not [string]::IsNullOrWhiteSpace($source_image) -and -not [string]::IsNullOrWhiteSpace($target_image)) {
                    # Store injection from source perspective
                    if (-not $process_injections.ContainsKey($source_guid)) {
                        $process_injections[$source_guid] = @()
                    }
                    
                    $injection_string = "→ $target_image"
                    if ($granted_access) { $injection_string += " (Access: $granted_access)" }
                    
                    if ($process_injections[$source_guid] -notcontains $injection_string) {
                        $process_injections[$source_guid] += $injection_string
                    }
                }
            }
            
            # Sysmon Rules/Techniques
            $rule_name = $row.'json.event.EventData.Data.RuleName'
            if (-not [string]::IsNullOrWhiteSpace($rule_name)) {
                if (-not $sysmon_rules.ContainsKey($process_r7id)) {
                    $sysmon_rules[$process_r7id] = @()
                }
                
                # Parse rule name for techniques (often in format "technique_id=T1234,technique_name=Something")
                $rules = $rule_name -split ','
                foreach ($rule in $rules) {
                    $rule = $rule.Trim()
                    if ($sysmon_rules[$process_r7id] -notcontains $rule) {
                        $sysmon_rules[$process_r7id] += $rule
                    }
                }
            }
            
        } catch {
            Write-Warning "Error parsing row: $_"
            Write-Warning $_.Exception.Message
        }
    }
    
    # PASS 1.5: Check ALL processes to see if they match force include pattern
    Write-Host "Checking all processes for force include patterns..."
    $force_include_count = 0
    foreach ($r7id in $all_processes.Keys) {
        $proc_name = $all_processes[$r7id].name
        if (Test-ForceInclude $proc_name) {
            if (-not $forced_processes.ContainsKey($r7id)) {
                $forced_processes[$r7id] = $true
                $force_include_count++
                Write-Host "  Force included: $proc_name (r7_id: $r7id)"
            }
        }
    }
    
    # Recursive function to include all descendants
    function Include-AllDescendants {
        param($parent_r7id, $include_dict)
        
        if ($all_children_map.ContainsKey($parent_r7id)) {
            foreach ($child_r7id in $all_children_map[$parent_r7id]) {
                if (-not $include_dict.ContainsKey($child_r7id)) {
                    $include_dict[$child_r7id] = $true
                    $child_name = $all_processes[$child_r7id].name
                    Write-Verbose "  Including child: $child_name (r7_id: $child_r7id)"
                }
                # Recursively include this child's children
                Include-AllDescendants $child_r7id $include_dict
            }
        }
    }
    
    # PASS 1.6: Include all descendants of forced processes
    Write-Host "Including all child processes of force-included processes..."
    $descendant_count_before = $forced_processes.Count
    foreach ($r7id in @($forced_processes.Keys)) {
        Include-AllDescendants $r7id $forced_processes
    }
    $descendant_count = $forced_processes.Count - $descendant_count_before
    Write-Host "  Added $descendant_count descendant processes"
    
    Write-Host "Total processes read: $($all_processes.Count)"
    Write-Host "Processes matching user filter: $($matched_processes.Count)"
    Write-Host "Processes force included (with descendants): $($forced_processes.Count)"
    Write-Host "Network connections found: $(($network_connections.Values | Measure-Object -Sum Count).Sum)"
    Write-Host "DNS queries found: $(($dns_queries.Values | Measure-Object -Sum Count).Sum)"
    Write-Host "Files created found: $(($files_created.Values | Measure-Object -Sum Count).Sum)"
    Write-Host "Process injections found: $(($process_injections.Values | Measure-Object -Sum Count).Sum)"
    
    # SECOND PASS: Walk up parent chains and include all ancestors
    Write-Host "Second pass: Including parent chains..."
    $processes_to_include = @{}
    
    # Start with all matched processes AND forced processes
    foreach ($r7id in $matched_processes.Keys) {
        $processes_to_include[$r7id] = $true
    }
    
    foreach ($r7id in $forced_processes.Keys) {
        $processes_to_include[$r7id] = $true
    }
    
    # Walk up parent chains - create a copy of keys to avoid modification during enumeration
    $r7ids_to_process = @($processes_to_include.Keys)
    foreach ($r7id in $r7ids_to_process) {
        # Walk up the parent chain
        $current_r7id = $r7id
        while ($all_parent_map.ContainsKey($current_r7id)) {
            $parent_r7id = $all_parent_map[$current_r7id]
            
            if (-not $all_processes.ContainsKey($parent_r7id)) {
                break  # Parent not in dataset
            }
            
            # Check if parent should be ignored (stops the chain)
            $parent_name = $all_processes[$parent_r7id].name
            if (Test-ShouldIgnore $parent_name) {
                Write-Verbose "Stopping parent chain at ignored process: $parent_name"
                break
            }
            
            # Include this parent
            $processes_to_include[$parent_r7id] = $true
            $current_r7id = $parent_r7id
        }
    }
    
    Write-Host "Total processes to include (with parent chains): $($processes_to_include.Count)"
    
    # THIRD PASS: Build parent map for included processes
    Write-Host "Third pass: Building final parent relationships..."
    $parent_map = @{}
    foreach ($child_r7id in $all_parent_map.Keys) {
        # Only include relationship if child is in our include list
        if ($processes_to_include.ContainsKey($child_r7id)) {
            $parent_r7id = $all_parent_map[$child_r7id]
            
            # Only add parent relationship if parent is ALSO in include list
            if ($processes_to_include.ContainsKey($parent_r7id)) {
                $parent_map[$child_r7id] = $parent_r7id
            }
        }
    }
    
    Write-Host "Total parent relationships in final tree: $($parent_map.Count)"
    
    # Build the process tree recursively
    function Build-ProcessTree {
        param($r7id, $visited)
        
        # Prevent infinite loops
        if ($visited.ContainsKey($r7id)) {
            Write-Warning "Circular reference detected for r7_id $r7id"
            return $null
        }
        
        if (-not $processes_to_include.ContainsKey($r7id)) {
            return $null
        }
        
        if (-not $all_processes.ContainsKey($r7id)) {
            Write-Warning "r7_id $r7id not found in process list"
            return $null
        }
        
        $visited[$r7id] = $true
        $proc = $all_processes[$r7id]
        
        # Find all children of this process (that are in our include list)
        $children = @()
        foreach ($child_r7id in $parent_map.Keys) {
            if ($parent_map[$child_r7id] -eq $r7id) {
                $child_proc = Build-ProcessTree $child_r7id $visited
                if ($child_proc) {
                    $children += $child_proc
                }
            }
        }
        
        # Get telemetry for this process
        $proc_files = if ($files_created.ContainsKey($r7id)) { $files_created[$r7id] } else { @() }
        $proc_network = if ($network_connections.ContainsKey($r7id)) { $network_connections[$r7id] } else { @() }
        $proc_dns = if ($dns_queries.ContainsKey($r7id)) { $dns_queries[$r7id] } else { @() }
        $proc_injections = if ($process_injections.ContainsKey($r7id)) { $process_injections[$r7id] } else { @() }
        $proc_rules = if ($sysmon_rules.ContainsKey($r7id)) { $sysmon_rules[$r7id] } else { @() }
        
        # Create output object
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
    
    # Processes with no parent relationship (in our filtered set)
    foreach ($r7id in $processes_to_include.Keys) {
        if (-not $parent_map.ContainsKey($r7id)) {
            $top_level += $r7id
        }
    }
    
    $top_level = $top_level | Sort-Object -Unique
    
    Write-Host "Top-level processes found: $($top_level.Count)"
    
    # Show some top-level process names
    $top_sample = 0
    foreach ($tr7id in $top_level) {
        if ($top_sample -lt 10) {
            Write-Host "  Top-level: $($all_processes[$tr7id].name) (PID: $($all_processes[$tr7id].pid)) [User: $($all_processes[$tr7id].user)]"
            $top_sample++
        }
    }
    
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
    
    # Add all top-level processes as children of root
    foreach ($r7id in $top_level) {
        $visited = @{}
        $proc_tree = Build-ProcessTree $r7id $visited
        if ($proc_tree) {
            $json.children += $proc_tree
        }
    }
    
    # Output to file
    $ofile = Join-Path $file_path "$system_name-r7.json"
    Write-Host "## Writing output to $ofile"
    Write-Host "Total top-level processes in output: $($json.children.Count)"
    
    # Calculate total processes in tree
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
}
