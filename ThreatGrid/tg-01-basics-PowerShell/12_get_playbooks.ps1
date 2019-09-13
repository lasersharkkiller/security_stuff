##### Status: In Progress #####
#
# Script Author: Ian Norton
# Creation Date: 20190910
#
# PowerShell converted scripts from https://github.com/CiscoSecurity/
# Script to see the different playbooks available to ThreatGrid

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


###Query
$api_query = "https://panacea.threatgrid.com/api/v3/configuration/playbooks?api_key=$key"
$agent_response = Invoke-RestMethod -Uri $api_query -Headers $api_headers -Method Get

ForEach-Object{
    Write-Host $agent_response.data[0].playbooks
}
