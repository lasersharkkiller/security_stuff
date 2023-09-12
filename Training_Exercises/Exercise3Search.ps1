#############################################################
######################Exercise #3 Search#####################
#############################################################

$AppendedList = @()
$CurrentDlls = Get-Process | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue | Sort-Object -Unique | Select-Object ModuleName,FileName,Size,Company,Description

foreach($CurrentDll in $CurrentDlls){

    $CurrentDllExtraMeta = Get-ChildItem $CurrentDll.FileName -ErrorAction SilentlyContinue | Get-AuthenticodeSignature | ` Select-Object -Property ISOSBinary,SignatureType,Status,SignerCertificate
#$CurrentDll
#$CurrentDllExtraMeta
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
    $AppendedList = $AppendedList + $AddThis
    
}
echo "############################################"
echo "### Certs Not Validated by Authenticode: ###"
echo "############################################"
$AppendedList | Where-Object {$_.Status -ne "Valid"} | ` Select-Object -Property ModuleName,Status
