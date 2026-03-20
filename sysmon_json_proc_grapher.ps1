$file_path = Read-Host "Provide the full path to all Sysmon EVTX (already converted to JSON) JSON files:"
$files = gci $file_path -Recurse -Filter *Sysmon*.json
$fcount = $files.Count
$counter = 0
foreach ($file in $files) {
    $counter++
    $fname = $file.FullName
    Write-Host "Working on $counter of $fcount - $fname"
    $pid_dict = @{}
    $pid_user_dict = @{}
    $pid_dns = @{} #DNSEvent (DNS query)
    $pid_connect = @{} #Network connection
    $pid_create = @{} #FileCreate
    $pid_time = @{} 
    $cli_dict = @{}
    $pname_dict = @{}
    $xprocess_dict = @{} #source - key, values destinations
    $rules_dict = @{}
    $hashes_dict = @{}
    $system_name = ($file.Name -Split "-")[1]
    Get-Content -Path $file.FullName -ReadCount 1 | ForEach-Object {
        $temp = ($_ | convertFrom-Json)
        $type = $temp.event.action
        $message = ($_ | convertFrom-Json).message
        $tpid = $null
        $tpguid = $null
        $ppguid = $null
        $pname = $null
        $ppname = $null
        $fcreate = $null
        $domain_name = $null
        $puser = $null
        $pcli = $null
        $cli = $null
        $targetguid = $null
        $sourceguid = $null
        $parent_pid = $null
        $ptime = $temp.event.created
        $fsha256 = $null
        $frules = @()
        function clean($item) {
            $item = $item -Replace "}",""
            $item = $item -Replace "{",""
            $item = $item.Trim()
            $item = $item.ToUpper()
            return $item
        }
        foreach ($line in ($message -Split "\n")) {
            if ($line -like "ProcessId*") {
                $tpid = ($line -Split ":")[1].Trim()
            }
            if ($line -like "ProcessGuid*") {
                $tpguid = ($line -Split ":")[1].Trim()
                $tpguid = clean $tpguid
                
            }
            if ($line -like "ParentProcessId*") {
                $parent_pid = ($line -Split ":")[1].Trim()
            }
            if ($line -like "ParentProcessGuid*") {
                $ppguid = ($line -Split ":")[1].Trim()
                $ppguid = clean $ppguid
            }
            if ($line -like "SourceProcessGuid*") {
                $sourceguid = ($line -Split ":")[1].Trim()
                $sourceguid = clean $sourceguid
            }
            if ($line -like "TargetProcessGuid*") {
                $targetguid = ($line -Split ":")[1].Trim()
                $targetguid = clean $targetguid
            }
            if ($line -like "SourceImage*") {
                $sourceimage = (($line -replace "SourceImage: ",'') -Split "\\")[-1]
                $sourceimage = $sourceimage.ToUpper().Trim()
            }
            if ($line -like "TargetImage*") {
                $targetimage = (($line -replace "TargetImage: ",'') -Split "\\")[-1]
                $targetimage = $targetimage.ToUpper().Trim()
            }
            if ($line -like "Image:*") {
                $pname = (($line -replace "Image: ",'') -Split "\\")[-1]
                $pname = $pname.ToUpper().Trim()
            }
            if ($line -like "ParentImage*") {
                $ppname = (($line -replace "ParentImage: ",'') -Split "\\")[-1]
                $ppname = $ppname.ToUpper().Trim()
            }
            if ($line -like "CommandLine*") {
                $cli = ($line -replace "CommandLine: ",'').Trim()
                $cli = $cli.ToUpper().Trim()
            }
            if ($line -like "ParentCommandLine*") {
                $pcli = ($line -replace "ParentCommandLine: ",'').Trim()
                $pcli = $pcli.ToUpper().Trim()
            }
            if ($line -like "User:*") {
                $user = ($line -Split ":")[1].Trim()
                $user = $user.ToUpper().Trim()
            }
            if ($line -like "ParentUser:*") {
                $puser = ($line -Split ":")[1].Trim()
                $puser = $puser.ToUpper().Trim()
            }
            if ($line -like "QueryName:*") {
                $domain_name = ($line -Split ":")[1].Trim()
                $domain_name = $domain_name.ToUpper().Trim()
            }
            if ($line -like "DestinationIp:*") {
                $dip = ($line -Split ":")[1].Trim()
            }
            if ($line -like "DestinationPort:*") {
                $dport = ($line -Split ":")[1].Trim()
            }
            if ($line -like "TargetFilename:*") {
                $fcreate = ($line -replace "TargetFilename: ",'').Trim()
                $fcreate = $fcreate.ToUpper().Trim()
            }
            if ($line -like "Hashes:*") {
                $fsha256_arr = ($line -replace "Hashes: ",'') -Split ","
                foreach ($hash in $fsha256_arr) {
                    if ($hash -like "SHA256*") {
                        $fsha256 = ($hash -Replace "SHA256=","").Trim().ToUpper()
                    }
                }
            }
            
            if ($line -like "RuleName:*") {
                $frule_arr = ($line -replace "RuleName: ",'') -Split ","
                foreach ($item in $frule_arr) {
                    if ($item -like "technique_name*") {
                        $frules += ($item -Replace "technique_name=","").Trim().ToUpper()
                    }
                }
            }
        
        }
        
        if ($frules.count -ne 0) {
            if ($tpguid -ne $null) {
                if ($pid_connect.ContainsKey($tpguid)) {
                    $rules_dict[$tpguid]+=$frules
                    $rules_dict[$tpguid] =  @($rules_dict[$tpguid] | Sort-Object | Get-Unique)
                } else {
                    $rules_dict[$tpguid]+=@()
                    $rules_dict[$tpguid]+=$frules
                    $rules_dict[$tpguid] =  @($rules_dict[$tpguid] | Sort-Object | Get-Unique)
                }
            }
        }
        if ($type -eq "Network connection") {
            $remote = $dip + ":" + $dport
            if ($pid_connect.ContainsKey($tpguid)) {
                $pid_connect[$tpguid]+=$remote
                $pid_connect[$tpguid] =  @($pid_connect[$tpguid] | Sort-Object | Get-Unique)
            } else {
                $pid_connect[$tpguid] = @()
                $pid_connect[$tpguid]+=$remote
                $pid_connect[$tpguid] =  @($pid_connect[$tpguid] | Sort-Object | Get-Unique)
            }
        
        }
        if ($type -eq "CreateRemoteThread") {
            
            if ($xprocess_dict.ContainsKey($sourceguid)) {
                $xprocess_dict[$sourceguid]+=$targetguid
                $xprocess_dict[$sourceguid] =  @($xprocess_dict[$sourceguid] | Sort-Object | Get-Unique)
            } else {
                $xprocess_dict[$sourceguid] = @()
                $xprocess_dict[$sourceguid]+=$targetguid
                $xprocess_dict[$sourceguid] =  @($xprocess_dict[$sourceguid] | Sort-Object | Get-Unique)
            }
            if ($pname_dict.ContainsKey($sourceguid)) {
                $pname_dict[$sourceguid]+=$sourceimage
                $pname_dict[$sourceguid] =  @($pname_dict[$sourceguid] | Sort-Object | Get-Unique)
            } else {
                $pname_dict[$sourceguid] = @()
                $pname_dict[$sourceguid]+=$sourceimage
                $pname_dict[$sourceguid] =  @($pname_dict[$sourceguid] | Sort-Object | Get-Unique)
            }
            if ($pname_dict.ContainsKey($targetguid)) {
                $pname_dict[$targetguid]+=$targetimage
                $pname_dict[$targetguid] =  @($pname_dict[$targetguid] | Sort-Object | Get-Unique)
            } else {
                $pname_dict[$targetguid] = @()
                $pname_dict[$targetguid]+=$targetimage
                $pname_dict[$targetguid] =  @($pname_dict[$targetguid] | Sort-Object | Get-Unique)
            }
        
        }
        if ($type -eq "FileCreate") {
        
            if ($pid_create.ContainsKey($tpguid)) {
                $pid_create[$tpguid]+=$fcreate
                $pid_create[$tpguid] =  @($pid_create[$tpguid] | Sort-Object | Get-Unique)
            } else {
                $pid_create[$tpguid] = @()
                $pid_create[$tpguid]+=$fcreate
                $pid_create[$tpguid] =  @($pid_create[$tpguid] | Sort-Object | Get-Unique)
            }
        }
        if ($type -eq "Process creation") {
            if ($fsha256 -ne $null) {
                if ($tpguid -ne $null) {
                    $hashes_dict[$tpguid] = $fsha256
                }
            }
            if (!($pid_time.ContainsKey($tpguid))) {
                $pid_time[$tpguid] = $ptime
            }
            if ($parent_pid -eq $null) {
                $parent_pid = 0
            }
            if ($pid_dict.ContainsKey($ppguid)) {
                $pid_dict[$ppguid]+=$tpguid
                $pid_dict[$ppguid] =  @($pid_dict[$ppguid] | Sort-Object | Get-Unique)
            } else {
                $pid_dict[$ppguid] = @()
                $pid_dict[$ppguid]+=$tpguid
                $pid_dict[$ppguid] =  @($pid_dict[$ppguid] | Sort-Object | Get-Unique)
            }
            if ($pid_user_dict.ContainsKey($ppguid)) {
                $pid_user_dict[$ppguid]+=$puser
                $pid_user_dict[$ppguid] =  @($pid_user_dict[$ppguid] | Sort-Object | Get-Unique)
            } else {
                $pid_user_dict[$ppguid] = @()
                $pid_user_dict[$ppguid]+=$puser
                $pid_user_dict[$ppguid] =  @($pid_user_dict[$ppguid] | Sort-Object | Get-Unique)
            }
            if ($pid_user_dict.ContainsKey($tpguid)) {
                $pid_user_dict[$tpguid]+=$user
                $pid_user_dict[$tpguid] =  @($pid_user_dict[$tpguid] | Sort-Object | Get-Unique)
            } else {
                $pid_user_dict[$tpguid] = @()
                $pid_user_dict[$tpguid]+=$user
                $pid_user_dict[$tpguid] =  @($pid_user_dict[$tpguid] | Sort-Object | Get-Unique)
            }
            if ($cli_dict.ContainsKey($tpguid)) {
                $cli_dict[$tpguid]+=$cli
                $cli_dict[$tpguid] =  @($cli_dict[$tpguid] | Sort-Object | Get-Unique)
            } else {
                $cli_dict[$tpguid] = @()
                $cli_dict[$tpguid]+=$cli
                $cli_dict[$tpguid] =  @($cli_dict[$tpguid] | Sort-Object | Get-Unique)
            }
            if ($cli_dict.ContainsKey($ppguid)) {
                $cli_dict[$ppguid]+=$pcli
                $cli_dict[$ppguid] =  @($cli_dict[$ppguid] | Sort-Object | Get-Unique)
            } else {
                $cli_dict[$ppguid] = @()
                $cli_dict[$ppguid]+=$pcli
                $cli_dict[$ppguid] =  @($cli_dict[$ppguid] | Sort-Object | Get-Unique)
            }
            if ($pname_dict.ContainsKey($tpguid)) {
                $pname_dict[$tpguid]+=$pname
                $pname_dict[$tpguid] =  @($pname_dict[$tpguid] | Sort-Object | Get-Unique)
            } else {
                $pname_dict[$tpguid] = @()
                $pname_dict[$tpguid]+=$pname
                $pname_dict[$tpguid] =  @($pname_dict[$tpguid] | Sort-Object | Get-Unique)
            }
            if ($pname_dict.ContainsKey($ppguid)) {
                $pname_dict[$ppguid]+=$ppname
                $pname_dict[$ppguid] =  @($pname_dict[$ppguid] | Sort-Object | Get-Unique)
            } else {
                $pname_dict[$ppguid] = @()
                $pname_dict[$ppguid]+=$ppname
                $pname_dict[$ppguid] =  @($pname_dict[$ppguid] | Sort-Object | Get-Unique)
            }
        } else {
            if ($ptime -ne $null) {
                if ($tpguid -ne $null ){
                    if (!($pid_time.ContainsKey($tpguid))) {
                        $pid_time[$tpguid] = $ptime
                    }
                }
            }
            if (($ppguid -ne $null) -and ($tpguid -ne $null)) {
                if ($pid_dict.ContainsKey($ppguid)) {
                    $pid_dict[$ppguid]+=$tpguid
                    $pid_dict[$ppguid] =  @($pid_dict[$ppguid] | Sort-Object | Get-Unique)
                } else {
                    $pid_dict[$ppguid] = @()
                    $pid_dict[$ppguid]+=$tpguid
                    $pid_dict[$ppguid] =  @($pid_dict[$ppguid] | Sort-Object | Get-Unique)
                }
            }
            if (($pname -ne $null) -and ($tpguid -ne $null)) {
                if ($pname_dict.ContainsKey($tpguid)) {
                    $pname_dict[$tpguid]+=$pname
                    $pname_dict[$tpguid] =  @($pname_dict[$tpguid] | Sort-Object | Get-Unique)
                } else {
                    $pname_dict[$tpguid] = @()
                    $pname_dict[$tpguid]+=$pname
                    $pname_dict[$tpguid] =  @($pname_dict[$tpguid] | Sort-Object | Get-Unique)
                }
            }
            if (($ppname -ne $null) -and ($ppguid -ne $null)) {
                if ($pname_dict.ContainsKey($ppguid)) {
                    $pname_dict[$ppguid]+=$ppname
                    $pname_dict[$ppguid] =  @($pname_dict[$ppguid] | Sort-Object | Get-Unique)
                } else {
                    $pname_dict[$ppguid] = @()
                    $pname_dict[$ppguid]+=$ppname
                    $pname_dict[$ppguid] =  @($pname_dict[$ppguid] | Sort-Object | Get-Unique)
                }
            }
        }
        if ($type -eq "DNSEvent (DNS query)") {
            if ($pid_dns.ContainsKey($tpguid)) {
                $pid_dns[$tpguid]+=$domain_name
                $pid_dns[$tpguid] =  @($pid_dns[$tpguid] | Sort-Object | Get-Unique)
            } else {
                $pid_dns[$tpguid] = @()
                $pid_dns[$tpguid]+=$domain_name
                $pid_dns[$tpguid] =  @($pid_dns[$tpguid] | Sort-Object | Get-Unique)
            }
        }
    }


    #find PID with no parent
    $top_level = @()
    foreach ($key in $pid_dict.Keys) {
        $exist = $false
        foreach ($tkey in $pid_dict.Keys) {
            if ($pid_dict[$tkey].Contains($key)) {
                $exist = $true
            }
        }
        if (!($exist)) {
            $top_level+=$key
        }
    }
    #list children keys
    #find PID with no parent
    $children_keys = @()
    foreach ($key in $pid_dict.Keys) {
        $children_keys+=$pid_dict[$key]
    }
    $children_keys = $children_keys | Sort-Object | Get-Unique
    #find interesting processes associated with Process Injections (to or from), with Connections, OR with External Domain Calls
    foreach ($key in $pname_dict.Keys) {
        if ($top_level -NotContains $key){
            $exist = $false
            if ($pid_connect[$key] -ne $null) {
                $exist = $true
            } 
            if ($pid_dns[$key] -ne $null) {
                $add = $false
                $domains = $pid_connect[$key] 
                foreach ($d in $domains) {
                    if (($d -like "*\.*") -and (($d -notlike "*local") -or ($d -notlike "*int") -or ($d -notlike "*pvt"))) {
                        $add = $true
                    }
                }
                if ($add) {
                    
                    $exist = $true
                }
            }
            if ($xprocess_dict[$key] -ne $null) {
                $exist = $true
            }
            
            if ($exist) {
                if ($children_keys -notcontains $key) {
                    $top_level+=$key
                }
            }
        }
    }
    $top_level = $top_level | Sort-Object | Get-Unique
    foreach ($xkey in $xprocess_dict.Keys) {
        foreach ($value in $xprocess_dict[$xkey]) {
            if ($top_level -NotContains $value) {
                $add = $true
                foreach ($key in $pid_dict.Keys) {
                    if ($pid_dict[$key] -Contains $value) {
                        $add = $false
                    }
                }
                if ($add) {
                    if ($children_keys -notcontains $key) {
                        $top_level+=$value
                    }
                }
            }
        }
    }
    $top_level = $top_level | Sort-Object | Get-Unique
    function build_process($tpid){
        $children = @()
        $children_process = $pid_dict[$tpid]
        $pname = $null
        $puser = $null
        $phash = $null
        $cli = $null
        $ptime = $null
        $files = $null
        $connections = $null
        $queries = $null
        $rules = $null
        $process_injections = $null
        if ($pname_dict[$tpid] -eq $null) {
            $pname = "Unknown"
        } else {
            $pname = $pname_dict[$tpid] | Out-string
        }
        if ($pid_user_dict[$tpid] -eq $null) {
            $puser = "Unknown"
        } else {
            $puser = $pid_user_dict[$tpid] | Out-string
        }
        if ($hashes_dict[$tpid] -eq $null) {
            $phash = "Unknown"
        } else {
            $phash = $hashes_dict[$tpid] | Out-string
        }
        if ($cli_dict[$tpid] -eq $null) {
            $cli = "Unknown"
        } else {
            $cli = $cli_dict[$tpid] | Out-string
        }
        $cli = $cli -Replace "Parent",""
        if ($pid_time[$tpid] -eq $null) {
            $ptime = "Unknown"
        } else {
            $ptime = $pid_time[$tpid] | Out-string
        }
        if (!(($cli -eq "Unknown") -and ($puser -eq "Unknown") -and ($pname -eq "Unknown") -and ($children_process.Count -eq 0))) {
            if ($pid_create[$tpid] -eq $null) {
                $files = @()
            } else {
                $files = $pid_create[$tpid]
            }
            if ($pid_connect[$tpid] -eq $null) {
                $connections = @()
            } else {
                $connections = $pid_connect[$tpid]
            }
            if ($pid_dns[$tpid] -eq $null) {
                $queries = @()
            } else {
                $queries = $pid_dns[$tpid]
            }
            if ($rules_dict[$tpid] -eq $null) {
                $rules = @()
            } else {
                $rules = $rules_dict[$tpid]
            }
            if ($xprocess_dict[$tpid] -eq $null) {
                $process_injections = @()
            } else {
                $temp_injections = $xprocess_dict[$tpid]
                $process_injections = @()
                foreach ($inj in $temp_injections) {
                    $tname = $pname_dict[$inj] | out-string
                    $t_inj = $tname + " - " + $inj
                    $process_injections+=$t_inj
                }
            }
            #build Child Processes
            foreach ($cprocess in $children_process) {
                $children+=build_process $cprocess
            }
            #check $pid_dict for children.....
            $output = New-Object -TypeName PSObject
            $output | Add-Member -MemberType NoteProperty -Name "name" -Value $pname
            $output | Add-Member -MemberType NoteProperty -Name "pid" -Value $tpid
            $output | Add-Member -MemberType NoteProperty -Name "sha256" -Value $phash
            $output | Add-Member -MemberType NoteProperty -Name "creation_time" -Value $ptime
            $output | Add-Member -MemberType NoteProperty -Name "user" -Value $puser
            $output | Add-Member -MemberType NoteProperty -Name "commandline" -Value $cli
            $output | Add-Member -MemberType NoteProperty -Name "files_created" -Value $files
            $output | Add-Member -MemberType NoteProperty -Name "network_connections" -Value $connections
            $output | Add-Member -MemberType NoteProperty -Name "dns_queries" -Value $queries
            $output | Add-Member -MemberType NoteProperty -Name "sysmon_rules" -Value $rules
            $output | Add-Member -MemberType NoteProperty -Name "process_injections" -Value $process_injections
            $output | Add-Member -MemberType NoteProperty -Name "children" -Value $children
            if ($pname.ToUpper() -notlike "*UPDATER.EXE*"){
                return $output
            }
        }
    }

    $json = New-Object -TypeName PSObject
    $json | Add-Member -MemberType NoteProperty -Name "name" -Value "root"
    $json | Add-Member -MemberType NoteProperty -Name "pid" -Value 0
    $json | Add-Member -MemberType NoteProperty -Name "sha256" -Value @()
    $json | Add-Member -MemberType NoteProperty -Name "user" -Value "SYSTEM"
    $json | Add-Member -MemberType NoteProperty -Name "commandline" -Value "SYSTEM PROCESS"
    $json | Add-Member -MemberType NoteProperty -Name "files_created" -Value @()
    $json | Add-Member -MemberType NoteProperty -Name "network_connections" -Value @()
    $json | Add-Member -MemberType NoteProperty -Name "dns_queries" -Value @()
    $json | Add-Member -MemberType NoteProperty -Name "sysmon_rules" -Value @()
    $json | Add-Member -MemberType NoteProperty -Name "process_injections" -Value @()
    $json | Add-Member -MemberType NoteProperty -Name "children" -Value @()
    foreach ($key in $top_level) {
        $json.children+= build_process $key
    }
    $ofile = $file_path + "\" + $system_name + ".json"
    Write-Host "## Writing output to $ofile"
    $json | ConvertTo-Json -Depth 100 | Out-File $ofile
}
