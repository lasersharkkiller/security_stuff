###############################
#                             #
#    ThreatGrid Hash Check    #
# Script Author: Cyber Panda  #
#                             #
###############################

Function Check-ThreatGridHash{

###ThreatGrid API key
$key = "<enter-api-key-here>"
$threatScore

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
$fileHash = Get-FileHash ($DLLPath) | Select-Object -ExpandProperty Hash

###Query
$api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?term=sample&q=$fileHash&api_key=$key"
$response = Invoke-RestMethod -Uri $api_query -Headers $api_headers -Method Get
$response.data
$total = $response.data.total

###Output the Threat Score and SHA256 from your organization
for ($n=0; $n -lt $total;$n++){
    if ($response.data.items[$n].item.analysis.threat_score){
        $temp = $response.data.items[$n].item.analysis.threat_score
        if($threatScore){
            if($temp > $threatScore){
                $threatScore = $temp
            }
        }
        else{
            $threatScore = $temp
        }
    }
    else{
        break;
    }
}
return $threatScore
}
