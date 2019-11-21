$computerHashes = Get-ChildItem -Force -Recurse C:\Users\Mary\Downloads | Get-FileHash -Algorithm SHA256
#$badHashes = Get-Content –Path C:\Users\Administrator\Documents\bad_hashes.txt
$VTApiKey = "b3e4e7058af66e877230e5730e92e1185ed6311deddd5a86eb46c0337c6a1bee"
$i=0

foreach($fileHash in $computerHashes){
    #foreach($line in $badHashes){
        #if($line -match $fileHash.Hash){
            $body = @{ resource = $fileHash.Hash; apikey = $VTApiKey }
            $VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
            $AVScanFound = @()

            if ($VTReport.positives -gt 0) {
            Write-Output $fileHash.Hash,$fileHash.Path >> C:\Users\Administrator\Desktop\test.txt
                foreach($scan in ($VTReport.scans | Get-Member -type NoteProperty)) {
                        if($scan.Definition -match "detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})") {
                        if($Matches.detected -eq "True") {
                        $AVScanFound += "{0}({1}) - {2}" -f $scan.Name, $Matches.version, $Matches.result
                        Write-Output $AVScanFound >> C:\Users\Administrator\Desktop\test.txt
                        }
                    }
                }
            #}
         #}
    }$i++
}

