### Step 1: Enumerate process with forensics artifacts according to SANS 508 +
### Step 2: Build in core processes from SANS 508 Known Normal Poster +
### Step 3: Add logic to test user paths +
### Step 4: Cross Reference Echo Trails for unknowns +
### Step 5: Add ability to toggle visibility for known / unknown / bad data
### Step 6: Add ability to toggle short / long data for each process
### Step 7: Add parameter addition to script
### Step 8: Add check for parent process; remember to factor in varied
### Step 9: Maybe added -matches for existing services to see if named similar
### Step 10: Add PS-Remoting
### Possible: In future maybe add network connection baseline?
### Possible: In future maybe add loaded libraries into memory?
### Possible: In future maybe add Echo Trails to database as you query to conserve API calls?

#############################################################
#######################Define Variables######################
#############################################################

#Define Echo Trails API Key 
$ETkey = "<enter-key-here>"

#Note I have baselined core processes into this script and then we reach out to Echo trails if it is not in the core baseline. The if statements normalize the data.
$CoreProcesses = Import-Csv -Path CoreProcessesBaseline.csv
foreach ($process in $CoreProcesses) {
    if ($process.ImagePath -eq "null"){
        $process.ImagePath = $null
    }
    if ($process.parentProc -eq "null"){
        $process.parentProc = $null
    }
    if ($process.UserAccount -eq "null"){
        $process.UserAccount = $null
    }
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

    Write-Output "- $SetStyleProcName Process Name: $($_.Name)$ResetStyle"
    Write-Output "   $SetStyleBelow Process id: ($($_.ProcessId)) Path: ($($_.Path)) Process Instances: ($tempNum) Process Owner: ($GetOwnerUser)$ResetStyle"
    Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth 1
}

Function Set-StyleChildrenProcs {
    $SetStyleProcName = "$($SetStyleBelow)$($PSStyle.bold)$($PSStyle.Underline)"

    $retTab + "- $SetStyleProcName Process Name: $($_.Name) $ResetStyle"
    $retTab + "  $SetStyleBelow Process id: ($($_.ProcessId)) Path: ($($_.Path)) Process Instances: ($tempNum) Process Owner: ($GetOwnerUser) $ResetStyle"
}
#############################################################
#############################################################
#############################################################


#############################################################
######################Echo Trails Logic######################
#############################################################
Function Check-EchoTrails-ChildrenProcs {
    #Look mostly at first results for each metadata
    $procName = 
    $ImagePath = $results.paths[0][0]
    $parentProc = $results.parents[0][0]
    $NumberOfInstances #Metadata doesn't exist with Echo Trails
    $UserAccount #Metadata doesn't exist with Echo Trails
    
    #The rest might be useful for expansion
    #$childProcs = $results.children
    #$grandParentProcs = $results.grandparents
    #$ports = $results.network
    #$procDescription = $results.$procDescription
    #$procIntel = $results.intel

    #Right now it only checks the image path, not # instances or the user context
    if(($_.Path -eq $ImagePath) -or ($_.Path -contains 'C:\Users\' -and $ImagePath -contains 'C:\Users\') -or ($_.Path -contains "C:\ProgramData" -and $ImagePath -contains 'C:\ProgramData\')){
        $SetStyleBelow = "$($PSStyle.Foreground.Green)"
    }
    else{
        $SetStyleBelow = "$($PSStyle.Foreground.Red)"
    }
    
    $SetStyleProcName = "$($SetStyleBelow)$($PSStyle.bold)$($PSStyle.Underline)"

    $retTab + "- $SetStyleProcName Process Name: $($_.Name) $ResetStyle"
    $retTab + "  $SetStyleBelow Process id: ($($_.ProcessId)) Path: ($($_.Path)) Process Instances: ($tempNum) Process Owner: ($GetOwnerUser) $ResetStyle"
}

Function Check-EchoTrails-RootProcs {
    #Look mostly at first results for each metadata
    $procName = 
    $ImagePath = $results.paths[0][0]
    $parentProc = $results.parents[0][0]
    $NumberOfInstances #Metadata doesn't exist with Echo Trails
    $UserAccount #Metadata doesn't exist with Echo Trails
    
    #The rest might be useful for expansion
    #$childProcs = $results.children
    #$grandParentProcs = $results.grandparents
    #$ports = $results.network
    #$procDescription = $results.$procDescription
    #$procIntel = $results.intel

    #Right now it only checks the image path, not # instances or the user context
    if(($_.Path -eq $ImagePath) -or ($_.Path -contains 'C:\Users\' -and $ImagePath -contains 'C:\Users\') -or ($_.Path -contains "C:\ProgramData" -and $ImagePath -contains 'C:\ProgramData\')){
        $SetStyleBelow = "$($PSStyle.Foreground.Green)"
    }
    else{
        $SetStyleBelow = "$($PSStyle.Foreground.Red)"
    }
    
    $SetStyleProcName = "$($SetStyleBelow)$($PSStyle.bold)$($PSStyle.Underline)"

    Write-Output "- $SetStyleProcName Process Name: $($_.Name)$ResetStyle"
    Write-Output "   $SetStyleBelow Process id: ($($_.ProcessId)) Path: ($($_.Path)) Process Instances: ($tempNum) Process Owner: ($GetOwnerUser)$ResetStyle"
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
        #Code to Add Process Count
        $Process = Get-CimInstance Win32_Process -Filter "name = `'$($_.Name)`'"
        $tempNum = $Process.count
        
        #Code to find Owner
        $pidQuery = Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE ProcessID = `'$($_.ProcessId)`'"
        $GetOwnerUser = (Invoke-CimMethod -InputObject $pidQuery -MethodName GetOwner).User

        #output
        $newDepth = $depth + 1

        if($_.Name -in $CoreProcesses.procName){
            $runningProc = $_.Name
            $CoreProcess = $CoreProcesses | Where-Object {$runningProc -eq $_.procName}
    
            #First Logic: Check the Path of the Executable. Note some values are null, especially root processes
            if(($_.Path -eq $CoreProcess.ImagePath) -or ($_.Path -contains 'C:\Users\' -and $CoreProcess.ImagePath -contains 'C:\Users\') -or ($_.Path -contains "C:\ProgramData" -and $CoreProcess.ImagePath -contains 'C:\ProgramData\')){
                
                if (($CoreProcess.NumberOfInstances -eq 1 -and $tempNum -eq $CoreProcess.NumberOfInstances) -or ($CoreProcess.NumberOfInstances -eq 2)) {

                    #Note this code block mostly checks for systems that should be running specifically under SYSTEM, LOCAL SERVICE, or NETWORK SERVICE
                    if (($CoreProcess.UserAccount -eq "MULTIPLE") -or ($CoreProcess.UserAccount -eq "SYSTEM" -and $GetOwnerUser -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq $null -and $GetOwnerUser -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "LOCAL SERVICE" -and $GetOwnerUser -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "NETWORK SERVICE" -and $GetOwnerUser -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -notin "SYSTEM","LOCAL SERVICE","NETWORK SERVICE" -or $CoreProcess.UserAccount -ne $null)){

                        $SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
                        Set-StyleChildrenProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
                    }
                    else{
                        $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                        Set-StyleChildrenProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
                    }
    
                }
                else{
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                    Set-StyleChildrenProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
                }
    
            }
            else{
                #First check if the value was null or the path starts with ProgramData
                if(($_.Path -eq $null)){
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightYellow)"
                    $SetStyleBelow
                    Write-Host("Expected a Path but our query returned a null value")
                    Set-StyleChildrenProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
                }
                else{
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                    Set-StyleChildrenProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
                }
            }
        }
        else{
            #Test Echo Trails
            $tempUri = 'https://api.echotrail.io/v1/private/insights/' + $_.Name
            $results = Invoke-RestMethod -Headers @{'X-Api-key' = $ETkey} -Uri $tempUri

            if ($results){
                Check-EchoTrails-ChildrenProcs(($($results)),($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
                $results = $null
            }

            else{
                #White Indicates No Baseline Data
                $SetStyleBelow = "$($PSStyle.Foreground.BrightWhite)"
                Set-StyleChildrenProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
            }

        }
        
        Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth $newDepth

    }
}

$allProcesses = Get-CimInstance -ClassName Win32_Process | Select-Object -Property Name,ProcessId,ParentProcessId,Path,UserName

$rootParents = $allProcesses | ForEach-Object {
    Get-RootParentProcess -process $_ -allProcesses $allProcesses
} | Select-object -Property Name,ProcessId,ParentProcessId,Path,UserName -Unique

$rootParents | ForEach-Object {
    #Code to Add Process Count
    $Process = Get-CimInstance Win32_Process -Filter "name = `'$($_.Name)`'"
    $tempNum = [string]$Process.count
        
    #Code to find Owner
    $pidQuery = Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE ProcessID = `'$($_.ProcessId)`'"
    $GetOwnerUser = (Invoke-CimMethod -InputObject $pidQuery -MethodName GetOwner).User

    
    #Check to see if it is in our core defined processes or if we need to get info from Echo Trails
    if($_.Name -in $CoreProcesses.procName){
        $runningProc = $_.Name
        $CoreProcess = $CoreProcesses | Where-Object {$runningProc -eq $_.procName}

        #First Logic: Check the Path of the Executable. Note some values are null, especially root processes
        if(($_.Path -eq $CoreProcess.ImagePath) -or ($_.Path -contains 'C:\Users\' -and $CoreProcess.ImagePath -contains 'C:\Users\') -or ($_.Path -contains "C:\ProgramData" -and $CoreProcess.ImagePath -contains 'C:\ProgramData\')){
            
            if (($CoreProcess.NumberOfInstances -eq 1 -and $tempNum -eq $CoreProcess.NumberOfInstances) -or ($CoreProcess.NumberOfInstances -eq 2)) {

                #Note this code block mostly checks for systems that should be running specifically under SYSTEM, LOCAL SERVICE, or NETWORK SERVICE
                if (($CoreProcess.UserAccount -eq "MULTIPLE") -or ($CoreProcess.UserAccount -eq "SYSTEM" -and $GetOwnerUser -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq $null -and $GetOwnerUser -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "LOCAL SERVICE" -and $GetOwnerUser -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -eq "NETWORK SERVICE" -and $GetOwnerUser -eq $CoreProcess.UserAccount) -or ($CoreProcess.UserAccount -notin "SYSTEM","LOCAL SERVICE","NETWORK SERVICE" -or $CoreProcess.UserAccount -ne $null)){
                    
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
                    Set-StyleRootProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
                }
                else{
                    $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                    Set-StyleRootProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
                }

            }
            else{
                $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                Set-StyleRootProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
            }

        }
        else{
            #First check if the value was null
            if($_.Path -eq $null){
                $SetStyleBelow = "$($PSStyle.Foreground.BrightYellow)"
                Write-Host("Expected a Path but our query returned a null value")
                Set-StyleRootProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
            }
            else{
                $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
                Set-StyleRootProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
            }
        }
    }
    else{
        #Test Echo Trails
        $tempUri = 'https://api.echotrail.io/v1/private/insights/' + $_.Name
        $results = Invoke-RestMethod -Headers @{'X-Api-key' = $ETkey} -Uri $tempUri

        if ($results){
            Check-EchoTrails-RootProcs(($($results)),($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
            $results = $null
        }

        else{
            #White Indicates No Baseline Data
            $SetStyleBelow = "$($PSStyle.Foreground.BrightWhite)"
            Set-StyleRootProcs(($($_.ProcessId)),($($_.Path)),($tempNum),($GetOwnerUser))
        }

    }
}
