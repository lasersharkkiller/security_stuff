<#
Original Source: https://discussions.qualys.com/thread/17309-powershell-with-qualys-vm-api

TOPIC
Qualys Vulnerbility Scan and Reporting

SHORT DESCRIPTION
This will output a pdf of the Vulnerbility Scan

LONG DESCRIPTION
The purpose of this script to to run a Vulnerbility Management Scan against a single
ip addres or a list of ip address. It will output a pdf in the same directory

EXAMPLES
.. Running a scan against multiple ip address downloading a xml using QualysScanner01 using the default Scan Profile and default Report Profile
Get-VMReports -qualysUsername "xxxx" -qualysPassword "P@ssw0rd" -scannerName "QualysScanner01" -reportType XML -ipAddress "10.10.10.10,10.10.10.11,10.10.10.12-10.10.10.20"

EXAMPLES
.. Running a scan against one ip address downloading a PDF using QualysScanner01 ,Scan Profile 123456 and Report Profile 234567
Get-VMReports -qualysUsername "xxxx" -qualysPassword "P@ssw0rd" -scannerName "QualysScanner01" -reportType PDF -ipAddress "10.10.10.10" -vmScanProfile -vmReportProfile

EXAMPLES
.. Running a scan against one ip address downloading a PDF against server 10.10.10.10 with vmProfile 123456 and vmReportProfile 234567
Get-VMReports -qualysUsername "xxxx" -qualysPassword "P@ssw0rd" -scannerName "Scanner" -reportType PDF -ipAddress "10.10.10.10" -vmScanProfile 123456 -vmReportProfile 234567

KEYWORDS
Qualys Vulnerbility Scan and Report

SEE ALSO
#>

Function Get-VMReports {
[CmdletBinding()]
Param(
[Parameter(Mandatory=$True,Position=1)]
[string]$qualysUsername,
[Parameter(Mandatory=$True,Position=2)]
[string]$qualysPassword,
[Parameter(Mandatory=$True,Position=3)]
[string]$scannerName,
#ReportType can be either pdf,html,mht,xml, or csv
[Parameter(Mandatory=$True,Position=4)]
[string]$reportType,
[Parameter(Mandatory=$True,Position=5)]
[string]$ipAddress
[Parameter(Position=6)]
[string]$vmScanProfile
[Parameter(Position=7)]
[string]$vmReportProfile
)

Begin {
CLS
}

Process{
$currentDate = Get-Date -Format "dMMMyyyy HHmm"
$title = "Windows Qualys VM " + "$hostName " + "$currentDate " + "- $qualysUsername"
$Outfile = "Qualys VM " + "$hostName - " + "$currentDate" +".$reportType"

#Setting the required Qualys url information
$Global:headers = @{"X-Requested-With"="powershell"}
$Global:baseUrl = "https://qualysapi.qualys.com/api/2.0/fo"
$Global:body = "action=login&username=$qualysUsername&password=$qualysPassword"

#Login and create an open session
Invoke-RestMethod -Headers $headers -Uri "$baseurl/session/" -Method Post -Body $body -SessionVariable websession

#Launch New Vunerability Management Scan
$vms = Invoke-RestMethod -Headers $headers -Uri "$baseUrl/scan/?action=launch&scan_title=$title&ip=$ipAddress&option_id=$vmScanProfile&iscanner_name=$scannerName" -Method Post -WebSession $webSession
$vmstext = ($vms).SIMPLE_RETURN.RESPONSE.TEXT
$s = [xml]$vms.SIMPLE_RETURN.RESPONSE.ITEM_LIST.OuterXml
[string]$Global:vmScanRef = ($s.ITEM_LIST.InnerText).remove(0,19)

if ($vmstext -like "*launched*"){
Write-host "New VM Scan started for $hostname"}
else {
Write-Host "The New VM Scan did not start becuase of " + $vmstext
Break
}

#Check to see if Scan Complete based on scan title.
function Get-ScanStatus {
Write-Host "Checking on Status of the Scan."
$Global:latestVMQualysScan = Invoke-RestMethod -Headers $headers -Uri "$baseurl/scan?action=list&scan_ref=$vmScanRef&show_last=1&show_status=1" -WebSession $webSession
if ($latestVMQualysScan.SCAN_LIST_OUTPUT.RESPONSE.SCAN_LIST.scan.STATUS.STATE -like "*Finished*"){
Write-Host "Scan is Finished"}
else {
start-sleep -Seconds 40
write-host "Scan still Running"
Get-ScanStatus
}
}

Get-ScanStatus

#Launch New Report base from the Scan
$vmr = Invoke-RestMethod -Headers $headers -Uri "$baseUrl/report/?action=launch&template_id=$vmReportProfile&report_title=$title&output_format=$reportType&ips=$ipAddress" -Method Post -WebSession $webSession
$vmrtext = ($vmr).SIMPLE_RETURN.RESPONSE.TEXT

$r = [xml]$vmr.SIMPLE_RETURN.RESPONSE.ITEM_LIST.OuterXml
[string]$Global:vmReportRef = ($s.ITEM_LIST.InnerText).remove(0,19)

if ($vmrtext -like "*launched*"){
Write-host "New VM Report started for $hostname"}
else {
Write-Host "The New VM Report did not start becuase of " + $vmrtext
Break
}

#Check to see if Report Complete
function Get-ReportStatus {
Write-Host "Checking on Status of the Report."
$Global:latestQualysReport = (Invoke-RestMethod -Headers $headers -Uri "$baseurl/report?action=list" -WebSession $webSession).SelectNodes("//REPORT[contains(TITLE, '$title')]")
if ($latestQualysReport.Status.OuterXml -like "*Finished*"){
Write-Host "Scan is Finished"
$global:reportID = $latestQualysReport.id}
else {
start-sleep -Seconds 10
write-host "Report still Running"
Get-ReportStatus
}
}

Get-ReportStatus

#Download the Report File
Invoke-RestMethod -Headers $headers -Uri "$baseUrl/report/?action=fetch&id=$reportID" -Method Post -WebSession $webSession -OutFile $outFile
}

End {
#Logout
Invoke-RestMethod -Headers $headers -Uri "$baseurl/session/" -Method Post -Body "action=logout" -WebSession $webSession
}

}
