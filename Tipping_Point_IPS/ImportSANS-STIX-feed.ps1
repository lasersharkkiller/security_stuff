########################Weekly Process in Tipping Point SMS#########################################
#One Time:
#1)	SMS / Profiles / Reputation Database / Tag Categories (Tab) / New
#2)	Name: “SANS Top IPs Blacklist”, Type: “Yes/No”, ok.
#3)	Profiles / Inspection Profiles / <select your perimeter profile> / Reputation / Geo
#4)	New Reputation / Name: “SANS Blacklist”, State: Enabled, Action Set: Block / Notify. In Entry Selection Criteria, make sure “SANS Top IPs Blacklist” is the only entry check, and select Tag value is Yes

#Weekly IPS Rhythm (until a TAXII server automates somewhat):
#1)	Run the script which outputs a CSV file called “SANSTopIPs.csv”
#2)	SMS / Profiles / Reputation Database / User Entries / Import / SANSTopIPs.csv
#3)	Click through defaults
####################################################################################################



########################Part 1: Pull IPs from SANS##################################################
#Troubleshooting Article: https://get-powershellblog.blogspot.com/2018/06/why-invoke-restmethod-and-convertfrom.html
#The commented code below should work normally but sometimes PowerShell has issues, had to come up with a custom script
#$WebResponse = Invoke-WebRequest "https://isc.sans.edu/api/topips/records/100?json"
#$WebResponse.content|ConvertFrom-Json|Select-Object

$browser = New-Object System.Net.WebClient
$browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials 

#Download a STIX feed for the top malicious IPs
$Uri = 'https://isc.sans.edu/api/topips/records/1000?json'
Invoke-RestMethod $Uri | 
    ForEach-Object {$_} | 
    Select-Object |
    select source |
    Export-Csv SANSTopIPs.csv



########################Part 2: Remove 0s used for Sorting###########################################

#Second part of script takes our output and takes out the duplicate zeros used for sorting (Trend Micro can't ingest)
$IPs = Import-Csv SANSTopIPs.csv

#Create Column Header
"IPs" | Out-File SANSTopIPs_Converted.csv

$output = ForEach ($IP in $IPs) {
   
    $IPShort = $IP.source  -replace '0*([0-9]+)', '${1}';
    $IPShort
} 
$output | Out-File SANSTopIPs_Converted.csv -Append

#Delete first csv
Remove-Item SANSTopIPS.csv


########################Part 3: Add Entries for Importing to Tipping Point SMS########################
#create an array from the csv file
$iplist = @(import-csv "SANSTopIPs_Converted.csv")

#create an empty array for output
$outarray = @()

#loop through each element in the array to retrieve Server name, mac and ip Address
foreach ( $entry in $iplist )
{

$colItems = 3

#populate array with results
    foreach ($item in $colitems)
    {
        $outarray += New-Object PsObject -property @{
        'IP' = $entry.IPs
        'RepEntry' = "SANS Top IPs Blacklist"
        'True' = "TRUE"
        }
    } 
}

#export to .csv file in the order Tipping Point needs it
$outarray | select IP,RepEntry,True| export-csv SANSTopIPs.csv

Remove-Item SANSTopIPs_Converted.csv