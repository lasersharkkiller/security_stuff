#
# Script Author: Ian the bitThirsty Hunter
# Creation Date: 20211014
#

#Define Echo Trail API key & Output file
$ETkey = "enter-API-key-here"
$outputFile = "C:\temp\Echo_Trail_Process_Check.txt"

#Get service exe paths of current processes
#Get-Unique help keeps API count down (only 250 allowed per day free)
$ProcPaths = Get-Process | Select-Object -ExpandProperty Path | Get-unique

$ProcPaths | ForEach-Object {
	#Get SHA256 hash of each exe (Echo Trail supports MD5/SHA256)
	$currHash = Get-FileHash $_ -Algorithm SHA256
		
	#parse the uri request with hash .. kept trying toString and it didnt work but this works so.. yeah
	$tempUri = 'https://api.echotrail.io/v1/private/insights/' + $currHash.Hash
	
	#Our piecemealed API request asking about our current hash
	$results = Invoke-WebRequest -Headers @{'X-Api-key' = $ETkey} -Uri $tempUri
	
	#Write results to file
	Add-Content $outputFile $_
	Add-Content $outputFile $currHash.Hash
	Add-Content $outputFile "`n"
	Add-Content $outputFile $results
	Add-Content $outputFile "-----------"	
}

[System.Windows.MessageBox]::Show('Script complete. Remember the lower the EPS score the more likely should dig into; the higher the score the more common of a regular process. This only analyzes the process file itself; not anything which may have been injected to memory. The output file is stored in C:\temp\Echo_Trail_Process_Check.txt".')
