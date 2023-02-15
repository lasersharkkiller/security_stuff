$notepadProc = Get-Process notepad
$notepadProc | Add-Member -MemberType ScriptProperty -Name VTPositives -Value {
$fileHash = Get-FileHash ($notepadProc.Path) | Select-Object -ExpandProperty Hash
$uri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apikey&resource=$fileHash"
Invoke-RestMethod -Uri $uri |Select-Object -ExpandProperty positives

#C:> $notepadProc.VTPositives
