[CmdletBinding()]
Param(
    [Parameter(Mandatory)]
    [alias("C")]
    $Config,
    [Parameter(Mandatory)]
    [alias("I")]
    $InFile,
    [Parameter(Mandatory)]
    [alias("O")]
    $outfile
    )
$ErrorActionPreference = "Stop"
$mapping = Get-Content $Config | ConvertFrom-Json
$parent_pid = $mapping.parent_pid
$parent_name = $mapping.parent_name
$parent_start = $mapping.parent_start
$child_pid = $mapping.child_pid
$child_name = $mapping.child_name
$child_start = $mapping.child_start
$child_cli = $mapping.child_cli
$ComputerName = $mapping.ComputerName
$filter_field = $mapping.filter_field
$event_filter = $mapping.event_filter
$ignore = $mapping.ignore -Split ","
If ($filter_field -like "*.*") {
    $filter_field = $filter_field -Split "\."
}
If ($parent_pid -like "*.*") {
    $parent_pid = $parent_pid -Split "\."
}
If ($parent_name -like "*.*") {
    $parent_name = $parent_name -Split "\."
}
If ($child_pid -like "*.*") {
    $child_pid = $child_pid -Split "\."
}
If ($ComputerName -like "*.*") {
    $ComputerName = $ComputerName -Split "\."
}
If ($child_name -like "*.*") {
    $child_name = $child_name -Split "\."
}
If ($child_cli -like "*.*") {
    $child_cli = $child_cli -Split "\."
}
#Is a file or directory
if ((Get-Item $InFile) -is [System.IO.DirectoryInfo]) {
    $InFiles = gci $InFile
    $temp = @()
    foreach ($tFile in $InFiles) {
        If ($tFile -like "*.csv") {
            $temp += Import-Csv $tFile
        }
        If ($tFile -like "*.json") {
            $temp += Get-Content $tFile | ConvertFrom-Json
        }
        If ($tFile -like "*.xml") {
            [xml]$temp += Get-Content $tFile
        }
        if ($event_filter -ne "") {
            if ($filter_field.GetType().BaseType.Name -eq "Array") {
                if ($filter_field.Count -eq 2) {
                    $1 = $filter_field[0]
                    $2 = $filter_field[1]
                    $temp = $temp | Where-Object {$_.$1.$2 -eq $event_filter}
                } elseif ($filter_field.Count -eq 3) {
                    $1 = $filter_field[0]
                    $2 = $filter_field[1]
                    $3 = $filter_field[2]
                    $temp = $temp | Where-Object {$_.$1.$2 -eq $event_filter}
                } else {
                    Write-Host "Too many periods in the Filter Field - only up to three supported currently"
                }

            } else {
                $temp = $temp | Where-Object {$_.$filter_field -eq $event_filter}
            }
        }
    }
} else {
    If ($InFile -like "*.csv") {
        $temp = Import-Csv $InFile
    }
    If ($InFile -like "*.json") {
        $temp = Get-Content $InFile | ConvertFrom-Json
    }
    If ($InFile -like "*.xml") {
        [xml]$temp = Get-Content $InFile
    }
    if ($event_filter -ne "") {
        if ($filter_field.GetType().BaseType.Name -eq "Array") {
            if ($filter_field.Count -eq 2) {
                $1 = $filter_field[0]
                $2 = $filter_field[1]
                $temp = $temp | Where-Object {$_.$1.$2 -eq $event_filter}
            } elseif ($filter_field.Count -eq 3) {
                $1 = $filter_field[0]
                $2 = $filter_field[1]
                $3 = $filter_field[2]
                $temp = $temp | Where-Object {$_.$1.$2 -eq $event_filter}
            } else {
                Write-Host "Too many periods in the Filter Field - only up to three supported currently"
            }

        } else {
            $temp = $temp | Where-Object {$_.$filter_field -eq $event_filter}
        }
    }
}



if ($ComputerName.GetType().BaseType.Name -eq "Array") {
    if ($ComputerName.Count -eq 2) {
        $1 = $ComputerName[0]
        $2 = $ComputerName[1]
        $Computer = $temp[0].$1.$2
    } elseif ($ComputerName.Count -eq 3) {
        $1 = $ComputerName[0]
        $2 = $ComputerName[1]
        $3 = $ComputerName[2]
        $Computer = $temp[0].$1.$2.$3
    }
} else {
    $Computer = $temp[0].$ComputerName
}
$vars = @()
$hashtable = @{}

$total = $temp.Count
$i = 0

foreach ($line in $temp) {
    $i++
    $ppid = $null
    $parent = $null
    if ($parent_pid.GetType().BaseType.Name -eq "Array") {
        if ($parent_pid.Count -eq 2) {
            $1 = $parent_pid[0]
            $2 = $parent_pid[1]
            $ppid = $line.$1.$2
        } elseif ($parent_pid.Count -eq 3) {
            $1 = $parent_pid[0]
            $2 = $parent_pid[1]
            $3 = $parent_pid[2]
            $ppid = $line.$1.$2.$3
        }
    } else {
        $ppid = $line.$parent_pid
    }
    if ($ppid -eq "") {
        $ppid = "0"
    }
    if ($parent_name.GetType().BaseType.Name -eq "Array") {
        if ($parent_name.Count -eq 2) {
            $1 = $parent_name[0]
            $2 = $parent_name[1]
            $pname = $line.$1.$2
        } elseif ($parent_name.Count -eq 3) {
            $1 = $parent_name[0]
            $2 = $parent_name[1]
            $3 = $parent_name[2]
            $pname = $line.$1.$2.$3
        }
    } else {
        $pname = $line.$parent_name
    }
    if ($pname -eq "") {
        $pname = "UNK_PNAME"
    }
    $parent = "$ppid ($pname)"
    if (!($vars -Contains $parent )) {
        if (!($ignore -Contains $pname)) {
            $vars += $parent
        }
    }
    $Completed = ($i/$total) * 100
    Write-Progress -Activity "Search in Progress" -Status "$i Out of $total Complete:" -PercentComplete $Completed
}
$vars = $vars | Select -Unique

foreach  ($item in $vars) {
    if ($item -ne "") {
        $hashtable[$item] = @()
    }
}
$total = $temp.Count
$i = 0
foreach ($line in $temp) {
    $i++
    $ppid = $null
    $cpid = $null
    if ($parent_pid.GetType().BaseType.Name -eq "Array") {
        if ($parent_pid.Count -eq 2) {
            $1 = $parent_pid[0]
            $2 = $parent_pid[1]
            $ppid = $line.$1.$2
        } elseif ($parent_pid.Count -eq 3) {
            $1 = $parent_pid[0]
            $2 = $parent_pid[1]
            $3 = $parent_pid[2]
            $ppid = $line.$1.$2.$3
        }
    } else {
        $ppid = $line.$parent_pid
    }
    if ($ppid -eq "") {
        $ppid = "0"
    }
    if ($parent_name.GetType().BaseType.Name -eq "Array") {
        if ($parent_name.Count -eq 2) {
            $1 = $parent_name[0]
            $2 = $parent_name[1]
            $pname = $line.$1.$2
        } elseif ($parent_name.Count -eq 3) {
            $1 = $parent_name[0]
            $2 = $parent_name[1]
            $3 = $parent_name[2]
            $pname = $line.$1.$2.$3
        }
    } else {
        $pname = $line.$parent_name
    }
    if ($pname -eq "") {
        $pname = "UNK_PNAME"
    }
    $parent = "$ppid ($pname)"
    if ($child_pid.GetType().BaseType.Name -eq "Array") {
        if ($child_pid.Count -eq 2) {
            $1 = $child_pid[0]
            $2 = $child_pid[1]
            $cpid = $line.$1.$2
        } elseif ($child_pid.Count -eq 3) {
            $1 = $child_pid[0]
            $2 = $child_pid[1]
            $3 = $child_pid[2]
            $cpid = $line.$1.$2.$3
        }
    } else {
        $cpid = $line.$child_pid
    }
    if ($cpid -eq "") {
        $cpid = "UNK_PID"
    }
    if ($child_name.GetType().BaseType.Name -eq "Array") {
        if ($child_name.Count -eq 2) {
            $1 = $child_name[0]
            $2 = $child_name[1]
            $cpname = $line.$1.$2
        } elseif ($child_name.Count -eq 3) {
            $1 = $child_name[0]
            $2 = $child_name[1]
            $3 = $child_name[2]
            $cpname = $line.$1.$2.$3
        }
    } else {
        $cpname = $line.$child_name
    }
    if ($cpname -eq "") {
        $cpname = "UNK_CPNAME"
    }
    $child = "$cpid ($cpname)"
    if (!($ignore -Contains $pname)) {
        if ($hashtable[$parent]) {
            if (!($hashtable[$parent].Contains($child))) {
                $hashtable[$parent] += $child
            }
        } else {
            $hashtable[$parent] = @()
            $hashtable[$parent] += $child
        }
    }
    $Completed = ($i/$total) * 100
    Write-Progress -Activity "Search in Progress" -Status "$i Out of $total Complete:" -PercentComplete $Completed
}

$noparents = @()
foreach ($var in $vars) {
    #does it exist as a child in any arrays?
    $ppid = $var
    $exist = "No"
    foreach ($item in $vars) {
        if ($hashtable[$item].Contains($ppid)) {
            $exist = "Yes"
        }
    }
    if ($exist -eq "No") {
        $noparents += $ppid
    }
}

#if no parent - these are child 2 and get linked to base name
function Get-Child {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$proc,
        [Parameter(Mandatory)]
        $level,
        [Parameter(Mandatory)]
        [string]$padding
    )
    $return_json = @()
    $children = $hashtable[$proc]
    if ($children.Count -gt 0) {
        $level++
        $json_level = 3938
        $padding = " " + $padding
        foreach ($child in $children) {
            $cpid = ($child -Split " ")[0]
            $cpname = ((($child -Split " ")[1] -Replace "\(","") -Replace "\)","").Trim()
            $ppid = ($proc -Split " ")[0]
            $pname = ((($proc -Split " ")[1] -Replace "\(","") -Replace "\)","").Trim()
            if ($parent_pid.GetType().BaseType.Name -eq "Array") {
                if ($parent_pid.Count -eq 2) {
                    $1 = $parent_pid[0]
                    $2 = $parent_pid[1]
                    $temp_temp = $temp | Where-Object {($_.$1.$2 -eq $ppid)}
                } elseif ($parent_pid.Count -eq 3) {
                    $1 = $parent_pid[0]
                    $2 = $parent_pid[1]
                    $3 = $parent_pid[2]
                    $temp_temp = $temp | Where-Object {($_.$1.$2.$3 -eq $ppid)}
                }
            } else {
                $temp_temp = $temp | Where-Object {$_.$parent_pid -eq $ppid}
            }
            if ($parent_name.GetType().BaseType.Name -eq "Array") {
                if ($parent_name.Count -eq 2) {
                    $1 = $parent_name[0]
                    $2 = $parent_name[1]
                    $temp_temp = $temp_temp | Where-Object {($_.$1.$2 -eq $pname)}
                } elseif ($parent_name.Count -eq 3) {
                    $1 = $parent_name[0]
                    $2 = $parent_name[1]
                    $3 = $parent_name[2]
                    $temp_temp = $temp_temp | Where-Object {($_.$1.$2.$3 -eq $pname)}
                }
            } else {
                $temp_temp = $temp_temp | Where-Object {$_.$parent_name -eq $pname}
            }
            if ($child_pid.GetType().BaseType.Name -eq "Array") {
                if ($child_pid.Count -eq 2) {
                    $1 = $child_pid[0]
                    $2 = $child_pid[1]
                    $temp_temp = $temp_temp | Where-Object {($_.$1.$2 -eq $cpid)}
                } elseif ($child_pid.Count -eq 3) {
                    $1 = $child_pid[0]
                    $2 = $child_pid[1]
                    $3 = $child_pid[2]
                    $temp_temp = $temp_temp | Where-Object {($_.$1.$2.$3 -eq $cpid)}
                }
            } else {
                $temp_temp = $temp_temp | Where-Object {$_.$child_pid -eq $cpid}
            }
            if ($child_cli.GetType().BaseType.Name -eq "Array") {
                if ($child_cli.Count -eq 2) {
                    $1 = $child_cli[0]
                    $2 = $child_cli[1]
                    $clis = $temp_temp.$1.$2
                } elseif ($child_cli.Count -eq 3) {
                    $1 = $child_cli[0]
                    $2 = $child_cli[1]
                    $3 = $child_cli[2]
                    $clis = $temp_temp.$1.$2.$3
                }
            } else {
                $clis = $temp_temp.$child_cli
            }
            $clis = $clis | Sort-Object | Get-Unique
            if ($child_start.GetType().BaseType.Name -eq "Array") {
                if ($child_start.Count -eq 2) {
                    $1 = $child_start[0]
                    $2 = $child_start[1]
                    $cstart = $temp_temp.$1.$2
                } elseif ($child_start.Count -eq 3) {
                    $1 = $child_start[0]
                    $2 = $child_start[1]
                    $3 = $child_start[2]
                    $cstart = $temp_temp.$1.$2.$3
                }
            } else {
                $cstart = $temp_temp.$child_start
            }
            if ($cstart.GetType().BaseType.Name -eq "Array") {
                $cstart = $cstart[0]
            }
            $temp_temp = $null
            foreach ($cli in $clis) {
                $lcli = $null
                $add = $false
                $lcli = $cli
                $cli = $cli[0..125] -Join ""
                if ($cli.Length -ge 125) {
                    $add = $true
                    $cli = $cli + "..."
                }
                $cli_level = 3938
                $cli = $cli -Replace '"',''
                $cli = $cli -Replace '\\','|'
                $lcli = $lcli -Replace '"',''
                $lcli = $lcli -Replace '\\','|'
                $item = "CLI - " + $cli
                $output = New-Object -TypeName PSObject
                $output | Add-Member -MemberType NoteProperty -Name "name" -Value $item
                if ($add) {
                    $output | Add-Member -MemberType NoteProperty -Name "cstart" -Value $lcli
                }
                $output | Add-Member -MemberType NoteProperty -Name "size" -Value $cli_level
                $return_json += $output | ConvertTo-Json
            }

            $output = New-Object -TypeName PSObject
            $output | Add-Member -MemberType NoteProperty -Name "name" -Value $child
            $output | Add-Member -MemberType NoteProperty -Name "size" -Value $json_level
            if ($cstart -ne "") {
                $output | Add-Member -MemberType NoteProperty -Name "cstart" -Value $cstart
            }
            $cchildren = $null
            $cchildren = Get-Child -proc $child -padding $padding -level $level
            if ($cchildren) {
                $output | Add-Member -MemberType NoteProperty -Name "children" -Value $cchildren
            }
            $return_json += $output | ConvertTo-Json
        }

    }
    if ($return_json.Count -gt 0) {
        $return_json = $return_json | Sort-Object | Get-Unique
        $final_children = "[" + ($return_json -Join ",") + "]"
        $return  = $final_children
    } else {
        $return = $null
    }
    return $return

}



#for each of these iterate trhough childdren and create sub levels
$total = $noparents.Count
$i = 0
$json = @()
foreach ($proc in $noparents) {
    $i++
    $Completed = ($i/$total) * 100
    Write-Progress -Activity "Search in Progress" -Status "$i Out of $total Complete:" -PercentComplete $Completed
    $ppid = ($proc -Split " ")[0]
    $pname = ((($proc -Split " ")[1] -Replace "\(","") -Replace "\)","").Trim()
    if ($parent_pid.GetType().BaseType.Name -eq "Array") {
        if ($parent_pid.Count -eq 2) {
            $1 = $parent_pid[0]
            $2 = $parent_pid[1]
            $temp_temp = $temp | Where-Object {($_.$1.$2 -eq $ppid)}
        } elseif ($parent_pid.Count -eq 3) {
            $1 = $parent_pid[0]
            $2 = $parent_pid[1]
            $3 = $parent_pid[2]
            $temp_temp = $temp | Where-Object {($_.$1.$2.$3 -eq $ppid)}
        }
    } else {
        $temp_temp = $temp | Where-Object {$_.$parent_pid -eq $ppid}
    }
    if ($parent_name.GetType().BaseType.Name -eq "Array") {
        if ($parent_name.Count -eq 2) {
            $1 = $parent_name[0]
            $2 = $parent_name[1]
            $temp_temp = $temp_temp | Where-Object {($_.$1.$2 -eq $pname)}
        } elseif ($parent_pid.Count -eq 3) {
            $1 = $parent_name[0]
            $2 = $parent_name[1]
            $3 = $parent_name[2]
            $temp_temp = $temp_temp | Where-Object {($_.$1.$2.$3 -eq $pname)}
        }
    } else {
        $temp_temp = $temp_temp | Where-Object {$_.$parent_name -eq $pname}
    }
    if ($parent_start.GetType().BaseType.Name -eq "Array") {
        if ($parent_start.Count -eq 2) {
            $1 = $parent_start[0]
            $2 = $parent_start[1]
            $pstart = $temp_temp.$1.$2
        } elseif ($parent_start.Count -eq 3) {
            $1 = $parent_start[0]
            $2 = $parent_start[1]
            $3 = $parent_start[2]
            $pstart = $temp_temp.$1.$2.$3
        }
    } else {
        $pstart = $temp_temp.$parent_start
    }
    $temp_temp = $null
    if ($pstart) {
        if ($pstart.GetType().BaseType.Name -eq "Array") {
            $pstart = $pstart[0]
        }
    } else {
        $pstart = "NA"
    }
    $level = 2
    $json_level = 3838
    $padding = "-"
    #Write-Host "$padding $proc"
    $output = New-Object -TypeName PSObject
    $output | Add-Member -MemberType NoteProperty -Name "name" -Value $proc
    try {
        $output | Add-Member -MemberType NoteProperty -Name "cstart" -Value $pstart
    } catch {
        $proc
    }
    $output | Add-Member -MemberType NoteProperty -Name "size" -Value $json_level
    try {
        $pchildren = Get-Child -proc $proc -padding $padding -level $level
    }catch {
        $proc
    }
    if ($pchildren.Count -gt 0) {
        $output | Add-Member -MemberType NoteProperty -Name "children" -Value $pchildren
    }
    $json += $output
}
$t =$json | ConvertTo-Json -Depth 100 -Compress
$t = $t -Replace "\\n",""
$t = $t -Replace "\\",""
$t = $t -Replace '"\[','['
$t = $t -Replace '\]"',']'
$t = $t -Replace "\|","\\"
$t = '{"children":' + $t
$t = $t + ',"name":"' + $Computer + '","size":3938}'
$t | out-File $outfile
Write-Host "Output written to $outfile"
