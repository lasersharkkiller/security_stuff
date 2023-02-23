### Step 1: Create a baseline of unique DLLs on first gold image +
### Step 2: Compare Name, Directory, Size, Company, Status against baseline +
### Step 3: If not in baseline check for invalid cert +
### Step 4: Then check for null values, if not, check baseline meta
### Step 5: Then check Hamming / Length Analysis
### Step 5: Optimize Frequency checks by consolidating unique baseline

#############################################################
#######################Define Variables######################
#############################################################
#Import HammingScore Function for name masquerading
# https://github.com/gravejester/Communary.PASM
$HammingScoreTolerance = 2 #Tune our Hamming score output
. ./FuzzyCheck/Get-HammingDistance.ps1

#Name Length Tolerance
$LengthTolerance = 6 #.dll is 4 chars

#Ability to import the latest definitions from GitHub:
$PullLatestBaseline = $false
if ($PullLatestBaseline){
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/cyb3rpanda/Threat-Hunter/main/baselines/BaselineDLLs.csv' -OutFile './baselines/BaselineDLLs.csv'
}

#Create / Clear our DLL output files
$unknownDLLsfile = './output/processHunting/unknownProcs.csv'
$anomalousDLLsfile = './output/processHunting/anomalousProcs.csv'
New-Item -ItemType File -Path $unknownDLLsfile -Force | Out-Null
New-Item -ItemType File -Path $anomalousDLLsfile -Force | Out-Null

$BaselineDLLs = Import-Csv -Path ./baselines/BaselineDLLs.csv
#############################################################
#############################################################
#############################################################

#############################################################
######################Frequency Analysis#####################
#############################################################
Function Hamming-Analysis {
    #Hamming Frequency Analysis against ModuleName, Company

    foreach($line in $BaselineDLL){

        if ($whichHammingAnalysis = "DLL Name"){
            $BaselineDLLMeta = [string]$line.ModuleName
            $StringRunDLLMeta = [string]$CurrentDLL.ModuleName
        }
        elseif ($whichHammingAnalysis = "Company"){
            $BaselineDLLMeta = [string]$line.Company
            $StringRunDLLMeta = [string]$CurrentDLL.Company
        }
        elseif ($whichHammingAnalysis = "Subject"){
            $BaselineDLLMeta = [string]$line.Subject
            $StringRunDLLMeta = [string]$CurrentDLL.SignerCertificate.Subject
        }
        elseif ($whichHammingAnalysis = "Issuer"){
            $BaselineDLLMeta = [string]$line.Issuer
            $StringRunDLLMeta = [string]$CurrentDLL.SignerCertificate.Issuer
        }
        elseif ($whichHammingAnalysis = "Serial"){
            $BaselineDLLMeta = [string]$line.Serial
            $StringRunDLLMeta = [string]$CurrentDLL.SignerCertificate.Serial
        }
        elseif ($whichHammingAnalysis = "Thumbprint"){
            $BaselineDLLMeta = [string]$line.Thumbprint
            $StringRunDLLMeta = [string]$CurrentDLL.SignerCertificate.Thumbprint
        }

        #First Analyze if in current meta


        #Do our actual analysis
        $HammingScore = Get-HammingDistance $StringRunDLLMeta $BaselineDLLMeta
        if ($HammingScore -le $HammingScoreTolerance){
            $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
            $SetStyleBelow
            $reason = "Similar naming but not the same for $($WhichOne)"
            $reason
        }
    }
}
Function Length-Analysis {
    #Length check of various metadata
    
        if ($CheckThisLength -le $LengthTolerance){
            $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
            $SetStyleBelow
            $reason = "Short name for $($WhichOne)"
            $reason
        }
}
#############################################################
#############################################################
#############################################################

#############################################################
#####################DLL General Baseline####################
#############################################################
Function DLL-Analysis {
    $reason = ""
    $BaselineDLL

    #Separate module to only do each unique DLL/exe once
    $SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
    $SetStyleBelow
    Write-Host("Gathering Currently Loaded Dlls...")
    $CurrentDlls = Get-Process | Select-Object -ExpandProperty Modules | sort -Unique | Select-Object ModuleName,FileName,Size,Company,Description
    Write-Host("Analyzing Against Baseline...")
    foreach($CurrentDll in $CurrentDlls){
        $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
        #$SetStyleBelow
        $CurrentDllExtraMeta = Get-ChildItem $CurrentDll.FileName | Get-AuthenticodeSignature | ` Select-Object -Property ISOSBinary,SignatureType,Status,SignerCertificate
        #Analyze against baseline DLLs - Status
        if($CurrentDll.ModuleName -in $BaselineDLLs.ModuleName){
            $reason = ""
            $BaselineDLL = $BaselineDLLs | Where-Object {$_.ModuleName -eq $CurrentDll.ModuleName}
            
            #First Check to make sure it's the same directory
            $CurrentDllFileName = [string]$CurrentDll.FileName
            if(([string]$BaselineDLL.FileName -eq "MULTIPLE") -or ($CurrentDllFileName -eq $BaselineDLL.FileName)){
                #Next we check to make sure it's the same size. Some malware appends to the end of legitamite DLLs
                if([int]$CurrentDll.Size -eq $BaselineDLL.Size){
                    #Next check the company
                    if([string]$CurrentDll.Company -eq $BaselineDLL.Company){
                        #Last check the status
                        if($CurrentDllExtraMeta.Status -eq $BaselineDLL.Status){
                        }
                        else{
                            $SetStyleBelow
                            $reason = "$($CurrentDllExtraMeta.Status) was not the same status as our baseline."
                            $reason
                        }
                    }
                    #Else Company did not match
                    else{
                        $SetStyleBelow
                        $reason = "$($CurrentDll.Company) was not the same size as our baseline. The company did not match"
                        $reason
                    }
                }
                #Else we failed the Size Check
                else{
                    $SetStyleBelow
                    $reason = "$($CurrentDll.ModuleName) was not the same size as our baseline. Some malware appends to the end of legitamite signed DLLs."
                    $reason
                }
            }
            #Else the DLL matched but it failed the directory check
            else{
                $SetStyleBelow
                $reason = "$($CurrentDll.FileName) was in the baseline list but didn't match the directory $($BaselineDLL.FileName)."
                $reason
            }
        }
        #If $CurrentDll.ModuleName -notin $BaselineDLLs.ModuleName look for various indicators
        else{
            $SetStyleBelow = "$($PSStyle.Foreground.BrightWhite)"
            $SetStyleBelow
            $reason = "$($CurrentDll.ModuleName) Not in our baseline."
            $reason
            $reason = "$($CurrentDll.ModuleName) Not in our baseline. Possible indicators: "

            #Invalid certs
            if([string]$CurrentDll.Status -ne "Valid"){
                $reason = "Not a valid certificate. "
            }

            #Maybe combine with check for null values
            #Hamming Frequency Analysis Against Module Name, Company, Subject, Issuer, Serial, Thumbprint
            $CheckThisLength = $CurrentDLL.ModuleName.Length
            $WhichOne = "DLL Name"
            Length-Analysis($CheckThisLength,$WhichOne)
            Hamming-Analysis($CurrentDll,$CurrentDllExtraMeta,$BaselineDLL,$WhichOne)

            if ($CurrentDll.Company -eq $null){
                $reason += "Company info is null. "
            }
            else{
                $CheckThisLength = $CurrentDLL.ModuleName.Length
                $WhichOne = "Company"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($CurrentDll,$CurrentDllExtraMeta,$BaselineDLL,$WhichOne)
            }
            
            if ($CurrentDllExtraMeta.SignerCertificate.Subject -eq $null){
                $reason += "Subject info is null. "
            }
            else{
                $CheckThisLength = $CurrentDllExtraMeta.SignerCertificate.Subject.Length
                $WhichOne = "Subject"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($CurrentDll,$CurrentDllExtraMeta,$BaselineDLL,$WhichOne)
            }

            if ($CurrentDllExtraMeta.SignerCertificate.Issuer -eq $null){
                $reason += "Issuer info is null. "
            }
            else{
                $CurrentDllExtraMeta = $CurrentDLL.CurrentDllExtraMeta.SignerCertificate.Issuer.Length
                $WhichOne = "Issuer"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($CurrentDll,$CurrentDllExtraMeta,$BaselineDLL,$WhichOne)
            }

            if ($CurrentDllExtraMeta.SignerCertificate.Serial -eq $null){
                $reason += "Serial info is null. "
            }
            else{
                $CheckThisLength = $CurrentDllExtraMeta.SignerCertificate.Serial.Length
                $WhichOne = "Serial"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($CurrentDll,$CurrentDllExtraMeta,$BaselineDLL,$WhichOne)
            }

            if ($CurrentDllExtraMeta.SignerCertificate.Thumbprint -eq $null){
                $reason += "Thumbprint info is null. "
            }
            else{
                $CheckThisLength = $CurrentDllExtraMeta.SignerCertificate.Thumbprint.Length
                $WhichOne = "Thumbprint"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($CurrentDll,$CurrentDllExtraMeta,$BaselineDLL,$WhichOne)
            }

            #Establish if EQUAL to list Issuers?

            #Make list of DLL Meta Unique

            #Name length analysis
        }
    }
    $SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
    $SetStyleBelow
}
#############################################################
#############################################################
#############################################################

#Invoke the main DLL Analysis function
DLL-Analysis
