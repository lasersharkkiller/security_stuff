### Step 1: Enumerate process with forensics artifacts according to SANS 508 +
### Step 2: Build in core processes from SANS 508 Known Normal Poster +
### Step 3: Add logic to compare baseline paths, # instances, user context +
### Step 4: Cross Reference Echo Trails for unknowns +
### Step 5: Add ability to output results to file(s) +
### Step 6: Set Reference File to match additional Echo Trails metadata +
### Step 7: Clean up & future proof variables being passed between functions +
### Step 8: Add check for parent process; figure out logic to parse multiple parents +
### Step 9: Logic for when Echo Trails doesn't recognize a process +
### Step 10: Hamming Frequency analysis to look for similar naming +
### Step 11: Add reasons for failures +
### Step 12: Logic for when Echo Trails API key runs out or doesnt work
### Step 13: Add PS-Remoting
### Step 14: After PS-Remoting, add host to Output Results
### Possible: After PS-Remoting add Long Tail analysis to anomalous results?
### Possible: Add freq.py / gravejester / day 4 functionality for other frequ analysis?
### Possible: Reference to look up process creation times for analysis, Handles, etc? 
### Possible: In future maybe add ability to download latest application definitions?
### Possible: In future maybe add network connection baseline? - Lab4.3 might be good reference; also lab5.2
### Possible: In future maybe add loaded libraries into memory?
### Definitely: Add module for Sigma hunting
### Possible: Add Get-ProcessMitigation <app> info (b4p23)?

#############################################################
#######################Define Variables######################
#############################################################
#Import HammingScore Function for name masquerading
# https://github.com/gravejester/Communary.PASM
$HammingScoreTolerance = 2 #Tune our Hamming score output
. ./FuzzyCheck/Get-HammingDistance.ps1

#Define Echo Trails API Key 
$ETkey = "0pWySfWK530M3pWAvcipaUsNyxNF9wC9AIVDma12"

#Create / Clear our output files
$goodfile = './output/processHunting/good.csv'
$unknownfile = './output/processHunting/unknown.csv'
$anomalousfile = './output/processHunting/anomalous.csv'
$fullDataNotReturned = './output/processHunting/fullDataNotReturned.csv'
$whichfile
New-Item -ItemType File -Path $goodfile -Force | Out-Null
New-Item -ItemType File -Path $unknownfile -Force | Out-Null
New-Item -ItemType File -Path $anomalousfile -Force | Out-Null
New-Item -ItemType File -Path $fullDataNotReturned -Force | Out-Null

#Keep track of current running Proc looking at
$RunningProcess
$Process
$reason
$MultipleParentTest = $false
#Import the CSV and normalize the data, for now null & multiple values in a cell
$CoreProcesses = Import-Csv -Path CoreProcessesBaseline.csv
foreach ($process in $CoreProcesses) {

    if (($process.ImagePath -eq "null") -or ($process.ImagePath -eq "")){
        $process.ImagePath = $null
    }
    if (($process.parentProc -eq "null") -or ($process.parentProc -eq "")){
        $process.parentProc = $null
    }
    if (($process.NumberOfInstances -eq "null") -or ($process.NumberOfInstances -eq "")){
        $process.NumberOfInstances = $null
    }
    if (($process.UserAccount -eq "null") -or ($process.UserAccount -eq "")){
        $process.UserAccount = $null
    }
    if (($process.ChildProcs -eq "null") -or ($process.ChildProcs -eq "")){
        $process.ChildProcs = $null
    }
    if (($process.GrandParentProcs -eq "null") -or ($process.GrandParentProcs -eq "")){
        $process.GrandParentProcs = $null
    }
    if (($process.Ports -eq "null") -or ($process.Ports -eq "")){
        $process.Ports = $null
    }
    if (($process.Notes -eq "null") -or ($process.Notes -eq "")){
        $process.Notes = $null
    }
}
#############################################################
#############################################################
#############################################################


#############################################################
#########################Append CSV##########################
#############################################################
Function Append-CSV {
    $csvfile
    #Processes matching baseline and unknowns have regular minimal data
    if (($whichfile -eq $goodfile)){
        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            NumberOfInstances = $RunningProcess.NumberOfInstances
            UserAccount = $RunningProcess.Owner
            Reason = $reason
        }
    }
    #Processes without full data include a reason column
    elseif (($whichfile -eq $fullDataNotReturned) -or ($whichfile -eq $unknownfile)) {
        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            ParentProcessId = $RunningProcess.ParentProcessID
            ParentProcess = $RunningProcess.ParentProcess
            NumberOfInstances = $RunningProcess.NumberOfInstances
            UserAccount = $RunningProcess.Owner
            Reason = $reason
        }
    }
    #Anomalous processes
    elseif ($whichfile -eq $anomalousfile) {
        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ExpectedProcessName = $CoreProcess.procName
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            ExpectedPath = $CoreProcess.ImagePath
            ParentProcessId = $RunningProcess.ParentProcessID
            ParentProcess = $RunningProcess.ParentProcess
            ExpectedParent = $CoreProcess.parentProc
            NumberOfInstances = $RunningProcess.NumberOfInstances
            ExpectedNumberofInstances = $CoreProcess.NumberOfInstances
            UserAccount = $RunningProcess.Owner
            ExpectedUserAccount = $CoreProcess.UserAccount
            ExpectedParentProc = $parentProc
            ExpecteDChildProcs = $childProcs
            ExpectedGrandParentProcs = $grandParentProcs
            ExpectedPorts = $ports
            Reason = $reason
            Notes = $intel
        }
    }
    
    $csvfile | Export-CSV $whichfile -Force –Append
}

Function Append-CSV-EchoTrails {
    #Processes matching baseline and unknowns have regular minimal data
Write-Output("Children:")
$results.children
Write-Output("grandparents:")
$results.grandparents
Write-Output("network conns:")
$results.network

        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ExpectedProcessName = $RunningProcess.Name
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            ExpectedPath =  $results.paths[0][0] + "\" + $RunningProcess.Name
            ParentProcessId = $RunningProcess.ParentProcessID
            ParentProcess = $RunningProcess.ParentProcess
            ExpectedParent = $results.parents[0][0]
            NumberOfInstances = $RunningProcess.NumberOfInstances
            ExpectedNumberofInstances = "ET doesn't have this data"
            UserAccount = $RunningProcess.Owner
            ExpectedUserAccount = "ET doesn't have this data"
            ExpectedChildProcs = ($results.children | Select-Object | Out-String)
            ExpectedGrandParentProcs = ($results.grandparents | Select-Object | Out-String)
            ExpectedPorts = ($results.network | Select-Object | Out-String)
            Reason = $reason
            Notes = $results.$intel
        }
    
    $csvfile | Export-CSV $whichfile -Force –Append
}

Function Append-CSV-NameFreqAnalysis {
    #Processes matching baseline and unknowns have regular minimal data
        
        $csvfile = [PSCustomObject]@{
            ProcessName = $RunningProcess.Name
            ExpectedProcessName = $StringCoreProcName
            ProcessId = $RunningProcess.ProcessId
            Path = $RunningProcess.Path
            ParentProcessId = $RunningProcess.ParentProcessID
            ParentProcess = $RunningProcess.ParentProcess
            NumberOfInstances = $RunningProcess.NumberOfInstances
            UserAccount = $RunningProcess.Owner
            Reason = $reason
        }
    
    $csvfile | Export-CSV $whichfile -Force –Append
}
#############################################################
#############################################################
#############################################################


#############################################################
##########Output Processes with Corresponding Style##########
#############################################################
$SetStyleProcName = "$($PSStyle.Foreground.BrightWhite)”; 
$SetStyleBelow = "$($PSStyle.Foreground.BrightWhite)”; 
$ResetStyle = "$($PSStyle.Reset)"

Function Set-StyleRootProcs {
        $SetStyleProcName = "$($SetStyleBelow)$($PSStyle.bold)$($PSStyle.Underline)"

        Write-Output "- $SetStyleProcName Name: $($_.Name)$ResetStyle"
        Write-Output "   $SetStyleBelow id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Process Instances: ($($RunningProcess.NumberOfInstances)) Process Owner: ($($RunningProcess.Owner))$ResetStyle"
        Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth 1
}

Function Set-StyleChildrenProcs {
        $SetStyleProcName = "$($SetStyleBelow)$($PSStyle.bold)$($PSStyle.Underline)"
        $retTab + "- $SetStyleProcName Name: $($_.Name) $ResetStyle"
        $retTab + "  $SetStyleBelow id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Process Instances: ($($RunningProcess.NumberOfInstances)) Process Owner: ($($RunningProcess.Owner)) $ResetStyle"
}
#############################################################
#############################################################
#############################################################


#############################################################
######################Echo Trails Logic######################
#############################################################
Function Check-EchoTrails-ChildrenProcs {
    #Look mostly at first results for each metadata
    $ImagePath = $results.paths[0][0] + "\" + $RunningProcess.Name

    #Right now it only checks the image path, not # instances or the user context
    if(($RunningProcess.Path -eq $ImagePath) -or ($RunningProcess.Path -contains 'C:\Users\' -and $ImagePath -contains 'C:\Users\') -or ($RunningProcess.Path -contains "C:\ProgramData" -and $ImagePath -contains 'C:\ProgramData\')){
            $SetStyleBelow = "$($PSStyle.Foreground.Green)"
            $SetStyleProcName = "$($SetStyleBelow)$($PSStyle.bold)$($PSStyle.Underline)"

            $retTab + "- $SetStyleProcName Name: $($_.Name) $ResetStyle"
            $retTab + "  $SetStyleBelow id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Instances: ($($RunningProcess.NumberOfInstances)) Owner: ($($RunningProcess.Owner)) $ResetStyle"

            #Add to file
            $whichfile = $goodfile
            Append-CSV-EchoTrails($($results))
    }
    else{
            $SetStyleBelow = "$($PSStyle.Foreground.Red)"
            $SetStyleProcName = "$($SetStyleBelow)$($PSStyle.bold)$($PSStyle.Underline)"

            $retTab + "- $SetStyleProcName Name: $($_.Name) $ResetStyle"
            $retTab + "  $SetStyleBelow id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Instances: ($($RunningProcess.NumberOfInstances)) Owner: ($($RunningProcess.Owner)) $ResetStyle"

            #Add to file
            $whichfile = $anomalousfile
            Append-CSV-EchoTrails($($results))
    }
}

Function Check-EchoTrails-RootProcs {
    #Look mostly at first results for each metadata
    $ImagePath = $results.paths[0][0] + "\" + $RunningProcess.Name

    #Right now it only checks the image path, not # instances or the user context
    if(($RunningProcess.Path -eq $ImagePath) -or ($RunningProcess.Path -contains 'C:\Users\' -and $ImagePath -contains 'C:\Users\') -or ($RunningProcess.Path -contains "C:\ProgramData" -and $ImagePath -contains 'C:\ProgramData\')){
        $SetStyleBelow = "$($PSStyle.Foreground.Green)"

        #Add to file
        $whichfile = $goodfile
        Append-CSV-EchoTrails($($results))
    }
    else{
        $SetStyleBelow = "$($PSStyle.Foreground.Red)"

        #Add to file
        $whichfile = $anomalousfile
        Append-CSV-EchoTrails($($results))
    }
    
    $SetStyleProcName = "$($SetStyleBelow)$($PSStyle.bold)$($PSStyle.Underline)"

    Write-Output "- $SetStyleProcName Name: $($_.Name)$ResetStyle"
    Write-Output "   $SetStyleBelow id: ($($_.ProcessId)) Path: ($($RunningProcess.Path)) Instances: ($($RunningProcess.NumberOfInstances)) Owner: ($($RunningProcess.Owner))$ResetStyle"
    Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth 1
}
#############################################################
#############################################################
#############################################################

#############################################################
######################Frequency Analysis#####################
#############################################################
Function Hamming-Analysis {
    #Processes matching baseline and unknowns have regular minimal data
    foreach($line in $CoreProcesses){
        $StringCoreProcName = [string]$line.procName
        $StringRunProcName = [string]$RunningProcess.Name
        $HammingScore = Get-HammingDistance $StringRunProcName $StringCoreProcName
        if ($HammingScore -le $HammingScoreTolerance){
            $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
            $SetStyleBelow
            $reason = "Very Similar to other host name"
            $reason
                            
            $whichfile = $anomalousfile
            Append-CSV-NameFreqAnalysis($StringCoreProcName)
            if($parentvschild = "child"){
                Set-StyleChildrenProcs
            }
            else{
                Set-StyleChildrenProcs
            } 
        }
    }
}
#############################################################
#############################################################
#############################################################



Function Get-RootParentProcess {
    Param($process,$allProcesses)

    #Check to see if a process exists for the Parent Process ID 
    if(($process.ParentProcessID -in $allProcesses.ProcessId) -and ($process.ProcessId -ne $process.ParentProcessId)){
        #If a parent process exists, call the function again, but inspect the parent process ID to see if there is another layer in the hierarchy
        $parentProcess = $allProcesses | Where-Object {$_.ProcessId -eq $process.ParentProcessId} | Select-object -Property Name,ProcessId,ParentProcessId,Path -Unique
        Get-RootParentProcess -process $parentProcess -allProcesses $allProcesses
    }
    else{ #if no parent Process ID exists, we're looking at a root parent process
        #Return the root parent
        $process
    }
}

Function Get-ChildProcesses { #Return all child processes for a given process
    Param($process,$allProcesses,$depth)
    $retTab = "  "*$depth
    $children = $allProcesses | Where-Object {($_.ParentProcessId -eq $process.ProcessId) -and ($_.ProcessId -ne $process.ProcessId)} | Select-Object -Property Name,ProcessId,ParentProcessId,Path -Unique

    $children | ForEach-Object {
    
    $reason = ""
    $Process = Get-CimInstance Win32_Process -Filter "name = `'$($_.Name)`'"
    $tempNum = [string]$Process.count
    
    #get owner
    $pidQuery = Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE ProcessID = `'$($_.ProcessId)`'"
    $owner = Invoke-CimMethod -InputObject $pidQuery -MethodName GetOwner
    $parentproc = Get-CimInstance Win32_Process -Filter "processid = `'$($_.ParentProcessID)`'"| Select-Object -Property Name,Path -Unique

    $RunningProcess = [PSCustomObject]@{
        PSTypename      = "ProcessHunting"
        ProcessID       = $_.ProcessID
        Name            = $_.Name
        Path            = $_.Path
        Handles         = $_.HandleCount
        WorkingSet      = $_.WorkingSetSize
        ParentProcessID = $_.ParentProcessID
        ParentProcess   = $parentproc.Name #these are root level procs
        ParentPath      = $parentproc.Path #these are root level procs
        Started         = $_.CreationDate
        Owner           = "$($owner.Domain)\$($owner.user)"
        CommandLine     = $_.Commandline
        NumberOfInstances = $tempNum
    }
        #output
        $newDepth = $depth + 1

        if($_.Name -in $CoreProcesses.procName){
            $runningProc = $_.Name
            $CoreProcess = $CoreProcesses | Where-Object {$runningProc -eq $_.procName}
    
            #First Logic: Check the Path of the Executable. Note some values are null, especially root processes
            if(($RunningProcess.Path -eq $CoreProcess.ImagePath) -or ($RunningProcess.Path -contains 'C:\Users\' -and $CoreProcess.ImagePath -contains 'C:\Users\') -or ($RunningProcess.Path -contains "C:\ProgramData" -and $CoreProcess.ImagePath -contains 'C:\ProgramData\')){

                #Loop through values, using $MultipleParentMatch to pass to next if
                $MultipleParentMatch = $false
                $TestForComma = [string]$CoreProcess.parentProc
                if($TestForComma -match (","))
                {
                    $tempParent = $TestForComma -split ","
                    foreach ($line in $tempParent){
                        if ($RunningProcess.ParentProcess -eq $line){
                            $MultipleParentMatch = $true
                        }
                        else{
                        }
                    }
                }

                if(($CoreProcess.ParentProc -eq "MULTIPLE") -or ($RunningProcess.ParentProcess -eq $CoreProcess.ParentProc) -or ($MultipleParentMatch)){
                    if (($CoreProcess.NumberOfInstances -eq 1 -and $RunningProcess.NumberOfInstances -eq $CoreProcess.NumberOfInstances) -or ($CoreProcess.NumberOfInstances -eq 2)) {
                        #Note this code block mostly checks for systems that should be running specifically under SYSTEM, LOCAL SERVICE, or NETWORK SERVICE
                        if (($CoreProcess.UserAccount -eq "MULTIPLE") -or ($CoreProcess.UserAccount -eq "SYSTEM" -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq $null -and ($($RunningProcess.Owner)) -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "LOCAL SERVICE" -and ($($RunningProcess.Owner)) -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "NETWORK SERVICE" -and ($($RunningProcess.Owner)) -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -notin "SYSTEM","LOCAL SERVICE","NETWORK SERVICE" -or $CoreProcess.UserAccount -ne $null)){
                            $SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
                            Set-StyleChildrenProcs
                            #Add to file
                            $whichfile = $goodfile
                            Append-CSV
                        }
                        else{
                            $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                            Set-StyleChildrenProcs
                            #Add to file
                            $whichfile = $anomalousfile
                            Append-CSV
                        }
                    }
                    else {
                        $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                        Set-StyleChildrenProcs
                        #Add to file
                        $whichfile = $anomalousfile
                        Append-CSV
                    }
                }
                else{
                    $reason = "Parent Process did not match"
                    Write-Output "($($RunningProcess.Name)) parent process ($($RunningProcess.ParentProcess)) Failed Against ($($CoreProcess.ParentProc))"
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                    $reason
                    Set-StyleChildrenProcs

                    #Add to file
                    $whichfile = $anomalousfile
                    Append-CSV
                }
            }
            else{
                #First check if the value was null
                if(($RunningProcess.Path -eq $null)){
                    $reason = "Expected a Path but our query returned a null value"
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightYellow)"
                    $SetStyleBelow
                    $reason
                    Set-StyleChildrenProcs

                    #Add to file
                    $whichfile = $fullDataNotReturned
                    Append-CSV($reason)
                }
                else{
                    $reason = "Paths did not match"
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                    $SetStyleBelow
                    $reason
                    Set-StyleChildrenProcs

                    #Add to file
                    $whichfile = $anomalousfile
                    Append-CSV
                }
            }
        }
        #else for if($_.Name -in $CoreProcesses.procName)
        else{

            #Before checking Echo Trails, analyze name frequency against baseline procs
            $parentvschild = "child"
            Hamming-Analysis($parentvschild)

            #Test Echo Trails
            $tempUri = 'https://api.echotrail.io/v1/private/insights/' + $_.Name
            $results = Invoke-RestMethod -Headers @{'X-Api-key' = $ETkey} -Uri $tempUri

            if($results.message -match "EchoTrail has never observed"){
                $reason = "Echo trails does not have this in the database"
                $reason
                #White Indicates No Baseline Data
                $SetStyleBelow = "$($PSStyle.Foreground.BrightWhite)"
                Set-StyleChildrenProcs
            
                #Add to file
                $whichfile = $unknownfile
                Append-CSV
            }

            elseif ($results){
                Check-EchoTrails-ChildrenProcs($($results))
                $results = $null
            }

            else{
                    $reason = "No baseline data"
                    #White Indicates No Baseline Data
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightWhite)"
                    Set-StyleChildrenProcs
                
                    #Add to file
                    $whichfile = $unknownfile
                    Append-CSV
            }

        }
        
        Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth $newDepth

    }
}

$allProcesses = Get-CimInstance -ClassName Win32_Process | Select-Object -Property Name,ProcessId,Path,HandleCount,WorkingSetSize,ParentProcessId,CreationDate,CommandLine,UserName

$rootParents = $allProcesses | ForEach-Object {
    Get-RootParentProcess -process $_ -allProcesses $allProcesses
} | Select-object -Property Name,ProcessId,Path,HandleCount,WorkingSetSize,ParentProcessId,CreationDate,CommandLine,UserName -Unique

$rootParents | ForEach-Object {
    $reason = ""
    #Count instances
    $Process = Get-CimInstance Win32_Process -Filter "name = `'$($_.Name)`'"
    $tempNum = [string]$Process.count

        #get owner
        $pidQuery = Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE ProcessID = `'$($_.ProcessId)`'"
        $owner = Invoke-CimMethod -InputObject $pidQuery -MethodName GetOwner
        #$parent = Get-Process -Id $item.ParentprocessID #these are root level procs
        $RunningProcess = [PSCustomObject]@{
            PSTypename      = "ProcessHunting"
            ProcessID       = $_.ProcessID
            Name            = $_.Name
            Path            = $_.Path
            Handles         = $_.HandleCount
            WorkingSet      = $_.WorkingSetSize
            ParentProcessID = $_.ParentProcessID
            #ParentProcess   = $parent.Name #these are root level procs
            #ParentPath      = $parent.Path #these are root level procs
            Started         = $_.CreationDate
            Owner           = "$($owner.Domain)\$($owner.user)"
            CommandLine     = $_.Commandline
            NumberOfInstances = $tempNum
        }
    
    #Check to see if it is in our core defined processes or if we need to get info from Echo Trails
    if($_.Name -in $CoreProcesses.procName){
        $runningProc = $_.Name
        $CoreProcess = $CoreProcesses | Where-Object {$runningProc -eq $_.procName}

        #First Logic: Check the Path of the Executable. Note some values are null, especially root processes
        if(($RunningProcess.Path -eq $CoreProcess.ImagePath) -or ($RunningProcess.Path -contains 'C:\Users\' -and $CoreProcess.ImagePath -contains 'C:\Users\') -or ($RunningProcess.Path -contains "C:\ProgramData" -and $CoreProcess.ImagePath -contains 'C:\ProgramData\')){
            if (($CoreProcess.NumberOfInstances -eq 1 -and $RunningProcess.NumberOfInstances -eq $CoreProcess.NumberOfInstances) -or ($CoreProcess.NumberOfInstances -eq 2)) {

                #Note this code block mostly checks for systems that should be running specifically under SYSTEM, LOCAL SERVICE, or NETWORK SERVICE
                if (($CoreProcess.UserAccount -eq "MULTIPLE") -or ($CoreProcess.UserAccount -eq "SYSTEM" -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq $null -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "LOCAL SERVICE" -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "NETWORK SERVICE" -and $RunningProcess.Owner -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -notin "SYSTEM","LOCAL SERVICE","NETWORK SERVICE" -or $CoreProcess.UserAccount -ne $null)){
                        $SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
                        Set-StyleRootProcs

                        #Add to file
                        $whichfile = $goodfile
                        Append-CSV
                }
                else{
                        $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                        $SetStyleBelow
                        $reason = "User context did not match"
                        $reason
                        Set-StyleRootProcs
                        
                        #Add to file
                        $whichfile = $anomalousfile
                        Append-CSV
                }

            }
            else{
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                    $SetStyleBelow
                    $reason = "Number of instances did not match"
                    $reason
                    Set-StyleRootProcs

                    #Add to file
                    $whichfile = $anomalousfile
                    Append-CSV
            }

        }
        else{
            #First check if the value was null
            if($RunningProcess.Path -eq $null){
                $SetStyleBelow = "$($PSStyle.Foreground.BrightYellow)"
                $SetStyleBelow
                $reason = "Expected a Path but our query returned a null value"
                $reason
                Set-StyleRootProcs

                #Add to file
                $whichfile = $fullDataNotReturned
                Append-CSV(($reason))
            }

            else{
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                    $SetStyleBelow
                    $reason = "Paths did not match"
                    $reason
                    Set-StyleRootProcs

                    #Add to file
                    $whichfile = $anomalousfile
                    Append-CSV
            }
        }
    }
    else{

        #Before checking Echo Trails, analyze name frequency against baseline procs
        $parentvschild = "parent"
        Hamming-Analysis($parentvschild)

        #Test Echo Trails
        $tempUri = 'https://api.echotrail.io/v1/private/insights/' + $_.Name
        $results = Invoke-RestMethod -Headers @{'X-Api-key' = $ETkey} -Uri $tempUri

        if($results.message -match "EchoTrail has never observed"){
            $reason = "Echo trails does not have this in the database"
            $reason
            #White Indicates No Baseline Data
            $SetStyleBelow = "$($PSStyle.Foreground.BrightWhite)"
            Set-StyleRootProcs
        
            #Add to file
            $whichfile = $unknownfile
            Append-CSV
        }

        elseif ($results){
            Check-EchoTrails-ChildrenProcs($($results))
            $results = $null
        }

        else{
                #White Indicates No Baseline Data
                $SetStyleBelow = "$($PSStyle.Foreground.BrightWhite)"
                Set-StyleTootProcs
                $reason = "No baseline data"
            
                #Add to file
                $whichfile = $unknownfile
                Append-CSV
        }

    }
}