##### Status: In Progress #####
#
# Script Author: Ian Norton
# Creation Date: 20190910
#
# PowerShell converted scripts from https://github.com/CiscoSecurity/
# Authentication format for ThreatGrid

###ThreatGrid API key
$key = "REPLACE-KEY-HERE"

###API header variable remains constant for all options
$api_headers = @{
"Content-Type"="application/json"
"User-Agent"="ThreatGrid API Script"
"Accept"="*/*"
"Cache-Control"="no-cache"
"Host"="panacea.threatgrid.com"
"Accept-Encoding"="gzip, deflate"
}

###Actual API Query Invoked; cap results to 100
$api_query = "https://panacea.threatgrid.com/api/v3/session/whoami?api_key=$key"
$agent_response = Invoke-RestMethod -Uri $api_query -Headers $api_headers -Method Get

#show response
Write-Host $agent_response.data[0]
