##### Status: In Progress #####
#
# Script Author: Ian Norton
# Creation Date: 20190910
#
# PowerShell converted scripts from https://github.com/CiscoSecurity/
# Script to search based off input

###ThreatGrid API key
$key = "REPLACE-YOUR-KEY-HERE"

###API header variable remains constant for all options
$api_headers = @{
"Content-Type"="application/json"
"User-Agent"="ThreatGrid API Script"
"Accept"="*/*"
"Cache-Control"="no-cache"
"Host"="panacea.threatgrid.com"
"Accept-Encoding"="gzip, deflate"
}

###Prompt for submission
$submission = Read-Host -Prompt 'Enter Submission Search Term'

###Query
$api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?q=$submission&api_key=$key"
$agent_response = Invoke-RestMethod -Uri $api_query -Headers $api_headers -Method Get
$total = $agent_response.data.total

###Output the Threat Score and SHA256
for ($n=0; $n -lt $total;$n++){
    if ($agent_response.data[0].items[$n].item.analysis.threat_score){
        Write-Host $n
        Write-Host $agent_response.data[0].items[$n].item.sha256
        }
}
