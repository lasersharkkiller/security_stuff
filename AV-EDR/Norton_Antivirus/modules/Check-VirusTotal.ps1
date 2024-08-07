Function Check-VirusTotal {
    #Set API Key
    $VTapikey = "<enter-api-key-here>"

    $fileHash = Get-FileHash ($DLLPath) | Select-Object -ExpandProperty Hash
    $uri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$VTapikey&resource=$fileHash"
    
    try {
        $VTPositives = Invoke-RestMethod -Uri $uri |Select-Object -ExpandProperty positives
        return $VTPositives
    } 
    catch {
        if ([string]$Error[0] -like "*(403) Forbidden.*"){
            Write-Host("Error reaching out to VirusTotal, most likely due to the API key missing.")
        }
        else{
            $reason = "Error reaching VirusTotal."
        }
    }
}
