### Step 1: Create a baseline of unique DLLs on first gold image +
### Step 2: Compare Name, Directory, Size, Company, Status against baseline +
### Step 3: If not in baseline check for invalid cert +
### Step 4: Then check for null values, if not, check baseline meta +
### Step 5: Then check Hamming / Length Analysis +
### Step 6: Add logic to skip valid, Trusted certs +
### Step 7: Move skipped certs statistical analysis to after known good iterated  +
### Step 8: Write unknown / anomalous to file +
### Step 9: Check if equal to list Issuers but not valid +
### Step 10: Freq.ps1 integration

#############################################################
#######################Define Variables######################
#############################################################
#Requires -RunAsAdministrator

#Import HammingScore Function for name masquerading
# https://github.com/gravejester/Communary.PASM
$HammingScoreTolerance = 2 #Tune our Hamming score output
. ./modules/Get-HammingDistance.ps1
. ./modules/Freq.ps1

#Name Length Tolerance
$LengthTolerance = 6 #.dll is 4 chars

#Ability to import the latest definitions from GitHub:
$PullLatestBaseline = $false
if ($PullLatestBaseline){
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/cyb3rpanda/Threat-Hunter/main/baselines/BaselineDLLs.csv' -OutFile './baselines/BaselineDLLs.csv'
}

#Create / Clear our DLL output files
$unknownDLLsfile = './output/Hunting/unknownDLLs.csv'
$anomalousDLLsfile = './output/Hunting/anomalousDLL.csv'
New-Item -ItemType File -Path $unknownDLLsfile -Force | Out-Null
New-Item -ItemType File -Path $anomalousDLLsfile -Force | Out-Null

$BaselineDLLs = Import-Csv -Path ./baselines/BaselineDLLs.csv
$TrustedCerts = Import-Csv -Path ./baselines/TrustedCerts.csv
$TrustedDLLs = @()
$FilesToCheck = @() #We save this to a list and check after building our TrustedDll List
#############################################################
#############################################################
#############################################################

#############################################################
######################Frequency Analysis#####################
#############################################################
Function Hamming-Analysis {
    #Hamming Frequency Analysis against ModuleName, Company

    foreach($line in $TrustedDLLs){

        if ($whichHammingAnalysis = "DLL Name"){
            $BaselineDLLMeta = [string]$line.ModuleName
            $StringRunDLLMeta = [string]$FileToCheck.ModuleName
        }
        elseif ($whichHammingAnalysis = "Company"){
            $BaselineDLLMeta = [string]$line.Company
            $StringRunDLLMeta = [string]$FileToCheck.Company
        }
        elseif ($whichHammingAnalysis = "Subject"){
            $BaselineDLLMeta = [string]$line.Subject
            $StringRunDLLMeta = [string]$FileToCheck.Subject
        }
        elseif ($whichHammingAnalysis = "Issuer"){
            $BaselineDLLMeta = [string]$line.Issuer
            $StringRunDLLMeta = [string]$FileToCheck.Issuer
        }
        elseif ($whichHammingAnalysis = "Serial"){
            $BaselineDLLMeta = [string]$line.Serial
            $StringRunDLLMeta = [string]$FileToCheck.Serial
        }
        elseif ($whichHammingAnalysis = "Thumbprint"){
            $BaselineDLLMeta = [string]$line.Thumbprint
            $StringRunDLLMeta = [string]$FileToCheck.Thumbprint
        }

        #Do our actual analysis
        $HammingScore = Get-HammingDistance $StringRunDLLMeta $BaselineDLLMeta
        if ($HammingScore -le $HammingScoreTolerance){
            $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
            $SetStyleBelow
            $reason += "Similar naming of $($StringRunDLLMeta) but not the same for $($BaselineDLLMeta)"
            $reason

            $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason
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
            
            $whichfile = $anomalousDLLsfile
            $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason
        }
}
#############################################################
#############################################################
#############################################################

#############################################################
#####################Filter Trusted DLLs#####################
#############################################################
Function Filter-TrustedDLLs {
    $reason = ""
    $BaselineDLL

    #Separate module to only do each unique DLL/exe once
    $SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
    $SetStyleBelow
    Write-Host("Gathering Currently Loaded Dlls...")
    $CurrentDlls = Get-Process | Select-Object -ExpandProperty Modules | sort -Unique | Select-Object ModuleName,FileName,Size,Company,Description
    Write-Host("Iterating Through Known Good...")
    foreach($CurrentDll in $CurrentDlls){
        $SetStyleBelow = "$($PSStyle.Foreground.BrightRed)"
        $CurrentDllExtraMeta = Get-ChildItem $CurrentDll.FileName | Get-AuthenticodeSignature | ` Select-Object -Property ISOSBinary,SignatureType,Status,SignerCertificate

        #Skip if valid and in our trust list, then add to our baseline for freq analysis
        if (($CurrentDllExtraMeta.Status -eq "Valid") -and ($CurrentDllExtraMeta.SignerCertificate.Subject -in $TrustedCerts.Subject)){
            $AddThis = New-Object PSObject -Property @{
                ModuleName      = $CurrentDll.ModuleName
                FileName        = $CurrentDll.FileName
                Size            = $CurrentDll.Size
                Company         = $CurrentDll.Company
                Description     = $CurrentDll.Description
                ISOSBinary      = $CurrentDllExtraMeta.ISOSBinary
                SignatureType   = $CurrentDllExtraMeta.SignatureType
                Status          = $CurrentDllExtraMeta.Status
                Subject         = $CurrentDllExtraMeta.SignerCertificate.Subject
                Issuer          = $CurrentDllExtraMeta.SignerCertificate.Issuer
                SerialNumber    = $CurrentDllExtraMeta.SignerCertificate.SerialNumber
                NotBefore       = $CurrentDllExtraMeta.SignerCertificate.NotBefore
                NotAfter        = $CurrentDllExtraMeta.SignerCertificate.NotAfter
                ThumbPrint      = $CurrentDllExtraMeta.SignerCertificate.ThumbPrint
            }
            $TrustedDLLs = $TrustedDLLs + $AddThis
        }

        elseif($CurrentDll.ModuleName -in $BaselineDLLs.ModuleName){
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
            $AddThis = New-Object PSObject -Property @{
                ModuleName      = $CurrentDll.ModuleName
                FileName        = $CurrentDll.FileName
                Size            = $CurrentDll.Size
                Company         = $CurrentDll.Company
                Description     = $CurrentDll.Description
                ISOSBinary      = $CurrentDllExtraMeta.ISOSBinary
                SignatureType   = $CurrentDllExtraMeta.SignatureType
                Status          = $CurrentDllExtraMeta.Status
                Subject         = $CurrentDllExtraMeta.SignerCertificate.Subject
                Issuer          = $CurrentDllExtraMeta.SignerCertificate.Issuer
                SerialNumber    = $CurrentDllExtraMeta.SignerCertificate.SerialNumber
                NotBefore       = $CurrentDllExtraMeta.SignerCertificate.NotBefore
                NotAfter        = $CurrentDllExtraMeta.SignerCertificate.NotAfter
                ThumbPrint      = $CurrentDllExtraMeta.SignerCertificate.ThumbPrint
            }
            $FilesToCheck = $FilesToCheck + $AddThis
        }
    }
    #After looping through known good analyze knowns
    Analyze-Unknowns
}
#############################################################
#############################################################
#############################################################

#############################################################
######################Analyze Unknowns#######################
#############################################################
Function Analyze-Unknowns {
    $SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
    $SetStyleBelow
    Write-Host("Analyzing unknowns ...")

    $SetStyleBelow = "$($PSStyle.Foreground.BrightYellow)"
    $SetStyleBelow

    foreach($FileToCheck in $FilesToCheck){
        $reason = "$($FileToCheck.ModuleName) Not in our valid trusted certs or baseline. Possible indicators: "
        $whichfile = $unknownDLLsfile

        #Hamming Frequency Analysis Against Module Name, Company, Subject, Issuer, Serial, Thumbprint
        $CheckThisLength = $FileToCheck.ModuleName.Length
        $WhichOne = "DLL Name"
        Length-Analysis($CheckThisLength,$WhichOne)
        Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)

        if($FileToCheck.Status -eq "NotSigned"){
            $reason = "Not signed. "

            $FileToCheck | Add-Member -Type NoteProperty -Name "reason" -Value $reason
            $FileToCheck | Export-CSV $whichfile -Force –Append
        }

        else{
            #Invalid certs
            if(($FileToCheck.Status -ne "Valid") -and ($FileToCheck.Issuer -in $TrustedDLLs.Issuer)){
                $reason += "Issued by a trusted issuer, but not a valid certificate. Some malware appends to legitamite DLLs. "
                $whichfile = $anomalousDLLsfile
            }

            #Invalid certs
            elseif([string]$FileToCheck.Status -ne "Valid"){
                $reason += "Not a valid certificate. "
                $whichfile = $anomalousDLLsfile
            }

            if ($FileToCheck.Company -eq $null){
                $reason += "Company info is null. "
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CheckThisLength = $FileToCheck.ModuleName.Length
                $WhichOne = "Company"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            }
            
            if ($FileToCheck.Subject -eq $null){
                $reason += "Subject info is null. "
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CheckThisLength = $FileToCheck.Subject.Length
                $WhichOne = "Subject"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            }

            if ($FileToCheck.Issuer -eq $null){
                $reason += "Issuer info is null. "
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CurrentDllExtraMeta = $FileToCheck.Issuer.Length
                $WhichOne = "Issuer"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            }

            if ($FileToCheck.Serial -eq $null){
                $reason += "Serial info is null. "
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CheckThisLength = $FileToCheck.Serial.Length
                $WhichOne = "Serial"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            }

            if ($FileToCheck.Thumbprint -eq $null){
                $reason += "Thumbprint info is null. "
                $whichfile = $anomalousDLLsfile
            }
            else{
                $CheckThisLength = $FileToCheck.Thumbprint.Length
                $WhichOne = "Thumbprint"
                Length-Analysis($CheckThisLength,$WhichOne)
                Hamming-Analysis($FileToCheck,$TrustedDLLs,$WhichOne)
            }
        }
        $FileToCheck | Export-CSV $whichfile -Force –Append
    }
}
#############################################################
#############################################################
#############################################################

#Invoke the main DLL Analysis function
Filter-TrustedDLLs
$SetStyleBelow = "$($PSStyle.Foreground.BrightGreen)"
$SetStyleBelow
