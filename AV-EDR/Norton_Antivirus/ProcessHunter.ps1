### Step 1: Enumerate processes with forensics artifacts according to SANS 508
### Step 2: To Do: Cross Reference Echo Trails
### Step 3: To Do: Color 

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

        #Set Styles
        $BoldUnderlineStyle = "$($PSStyle.bold)$($PSStyle.Underline)"
        $ResetStyle = "$($PSStyle.Reset)"
        
        #output
        $newDepth = $depth + 1
        $retTab + "- $BoldUnderlineStyle Process Name: $($_.Name) $ResetStyle"
        $retTab + "   Process id: ($($_.ProcessId)) Path: ($($_.Path)) Process Instances: ($tempNum) Process Owner: ($GetOwnerUser)"
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
    $tempNum = $Process.count
        
    #Code to find Owner
    $pidQuery = Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE ProcessID = `'$($_.ProcessId)`'"
    $GetOwnerUser = (Invoke-CimMethod -InputObject $pidQuery -MethodName GetOwner).User

    #Set Styles
    $BoldUnderlineStyle = "$($PSStyle.bold)$($PSStyle.Underline)"
    $ResetStyle = "$($PSStyle.Reset)"
    
    Write-Output "- $BoldUnderlineStyle Process Name: $($_.Name)" $ResetStyle
    Write-Output "   Process id: ($($_.ProcessId)) Path: ($($_.Path)) Process Instances: ($tempNum) Process Owner: ($GetOwnerUser)"
    Get-ChildProcesses -process $_ -allProcesses $allProcesses -depth 1
}
