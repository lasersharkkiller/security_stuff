##### Status: Complete #####
#
# Script Author: Ian Norton
# Creation Date: 20190726
#
# This script will send a request for S1 to upload blocked files to S1,
# Then it will pull down those blocked files. This script is meant to be
# run on a scheduled task OFF NETWORK. Note $threat_file_available has limit in url
# Change variables as needed: $cur_time.AddHours(-24); $api_Token; $our_site; $To/$From
# ThreatGrid variables: $key $currentfile $password and $files folder
# Also make sure c:\scripts exists if you log errors to $txt_file
# You may need to adjust the sleep period before downloading threat files (Start-Sleep...)
 
Add-Type -AssemblyName System.Web
 
#####################
##### Variables #####
#####################
#### Getting Time Range #####
$cur_time = Get-Date
$time_to_look_from = $cur_time.AddHours(-24) #Set the number of hours back for query. If on cron job how many hours between runs.
$zulu_time = Get-Date $time_to_look_from.ToUniversalTime().ToString() -Format "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"
$encoded_time = [System.Web.HttpUtility]::UrlEncode($zulu_time)
 
#### API Related ####
$api_Token = "INSERT-YOUR-TOKEN-HERE"
$our_site = "INSERT-YOUR-SITE-HERE"
$threat_data = "https://$our_site.sentinelone.net/web/api/v2.0/threats?limit=100&createdAt__gte=$encoded_time"
$fetch_data = "https://$our_site.sentinelone.net/web/api/v2.0/threats/fetch-file"
$threat_file_available = "https://$our_site.sentinelone.net/web/api/v2.0/activities?includeHidden=false&limit=100&activityTypes=86&createdAt__gte=$encoded_time"
 
Write-Host $zulu_time
Write-Host $threat_data
#### Other Variables ####
$txt_file = "c:\scripts\SentinelOne_Has_SentinelOne.txt"
$cursor = "FIRSTnotNull"
$threat_list = ""
$ts = New-TimeSpan -Hours 1
$DateTime1HourAgo = (Get-Date) - $ts
$fetchdatabody = ""
########################
##### Main Program #####
########################
#
##### Get AGENT DATA FIRST PASS#####
#
##### CONFIGURE HTTP HEADER FOR FIRST AGENT DATA API CALL #####
$api_headers = @{
"Authorization"="APIToken $api_token"
"Content-Type"="application/json"
}
#### CONFIGURE HTTP QUERY STRING FOR FIRST AGENT DATA API CALL  ####
$cursor = $threat_response.pagination.nextCursor
$api_query = @{
"isDecommissioned"="False"
}
Write-Host "Starting Now"
#### QUERY THE API FIRST TIME FOR THREAT FILES ####
try {
        $threat_response = Invoke-RestMethod -Uri $threat_data -Headers $api_headers -Method Get
        Write-Host "Getting Threats"
    } #end try
catch {
        
        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
       
        $err_object = $_ | ConvertFrom-Json
        Write-Host "Error Title:" $err_object.errors.title
        $err_object.errors.title | Out-File -FilePath $txt_file
        ### SEND EMAIL WITH ERROR INFO ###
        #$To = ("admin@company.com")
        #$From = "admin@company.com" #origination account for status emails
        #$SMTPServer = "mailhub.nscorp.com"; #system to process status email
        #$subject = "SentinelOne - Pull Malware Error"
        #$body="Error Title: " + $err_object.errors.title + "`n`n"
        #$body = $body += "Most likely need to update API Key located in script running on malware laptop"
        #Send-MailMessage -SmtpServer $SMTPServer -Subject $subject -Body $body -to $To -From $From
        } #end catch
#### BUILD LIST OF NAMES FROM CURRENT RESPONSE ####
 
$n=0
foreach ($threatdate in $threat_response.data.createdAt){
    Write-Host "Found Threat:"
    Write-Host $threat_response.data.createdAt[$n] `n
    Write-Host $threat_response.data.mitigationStatus[$n] `n
    Write-Host $threat_response.data.id[$n] `n
    #for some reason I have to set this as a variable to feed into the POST Body request instead of just setting $threat_response.data.id[$n] directly in the body
    $tmptid = $threat_response.data.id[$n]
   
    ##### Fetch Data to the S1 console from the endpoints  #####
    $fetchdatabody = @{
        filter= @{
            ids = "$tmptid"
        }
        data = @{
            password = "INFECTEDfiles"
        }
    } | ConvertTo-Json -Depth 3
      
    try {
        $threat_post_response = Invoke-RestMethod -UseBasicParsing -Uri $fetch_data -Headers $api_headers -Method POST -Body $fetchdatabody       
    } #end try
 
    catch {        
        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
       
        $err_object = $_ | ConvertFrom-Json
        Write-Host "Error Title:" $err_object.errors.title
        $err_object.errors.title | Out-File -FilePath $txt_file
    } #end catch
    $n++
}
 
#### QUERY THE API FOR THREAT FILES DOWNLOADED ####
try {
    $threat_files_avilable_response = Invoke-RestMethod -Uri $threat_file_available -Headers $api_headers -Method Get
    Write-Host "Made it to try and fetch data"
} #end try
 
catch {
    
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
   
    $err_object = $_ | ConvertFrom-Json
    Write-Host "Error Title:" $err_object.errors.title
    $err_object.errors.title | Out-File -FilePath $txt_file
 
    ### SEND EMAIL WITH ERROR INFO ###
    #$To = ("admin@company.com")
    #$From = "admin@company.com" #origination account for status emails
    #$SMTPServer = "mailhub.nscorp.com"; #system to process status email
    #$subject = "SentinelOne - Pull Malware Error"
    #$body="Error Title: " + $err_object.errors.title + "`n`n"
    #$body = $body += "Most likely need to update API Key located in script running on malware laptop"
    #Send-MailMessage -SmtpServer $SMTPServer -Subject $subject -Body $body -to $To -From $From
 
    } #end catch
 
#### BUILD LIST OF FILES FROM RESPONSE ####
Start-Sleep -Seconds 600 #First wait 10 minutes
$n=0
foreach ($threatdate in $threat_files_avilable_response.data.createdAt){
    Write-Host "Data to Download"
    Write-Host $threat_files_avilable_response.data.createdAt[$n] `n
    Write-Host $threat_files_avilable_response.data.id[$n] `n
    Write-Host $threat_files_avilable_response.data.data.filename[$n] `n
 
    $filename = $threat_files_avilable_response.data.data.filename[$n] + ".zip"
    $threat_file_download = "https://$our_site.sentinelone.net/web/api/v2.0" + $threat_files_avilable_response.data.data.filePath[$n]
 
    Write-Host $threat_file_download `n
    try {
        Invoke-WebRequest -Uri  $threat_file_download -Headers $api_headers -Method GET -OutFile $filename
    } #end try
    catch {
        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
        $err_object = $_
        Write-Host "Error Title:" $err_object.errors.title
        $err_object.errors.title | Out-File -FilePath $txt_file
    } #end catch
    $n++
}



#for unzip/rezip (password issues)
Import-Module -Name 7Zip4Powershell


###############################
#                             #
#    ThreatGrid Submission    #
#                             #
###############################

###ThreatGrid API key
$key = "INSERT-YOUR-KEY-HERE"
$password = "infected"
$files = Get-ChildItem "C:\bits\" -Filter *.zip

###API header variable
$api_headers = @{
"Content-Type"="multipart/form-data"
"User-Agent"="ThreatGrid API Script"
"Accept"="*/*"
"Cache-Control"="no-cache"
"Host"="panacea.threatgrid.com"
"Accept-Encoding"="gzip, deflate"
}

###FILE Operation

#Loop through .zip files in bits folder
for ($i=0; $i -lt $files.Count; $i++) {
$currentfile = $files[$i].FullName
    Write-Host $files.Count

    $newcurrentfile = "S1fileReZipped.zip"
    Expand-7Zip -ArchiveFileName $currentfile -Password "INFECTED123!" -TargetPath "C:\BITS\temp\tempfolder\"
    Compress-7Zip -Path C:\BITS\temp\tempfolder\ -ArchiveFileName C:\BITS\temp\$newcurrentfile -Format Zip -Password "infected"
    $newfile = Get-ChildItem "C:\bits\temp" -Filter *.zip
    $filetosend = $newfile[0].FullName

	    # Read the file contents in as a byte array
		$fileName = Split-Path $filetosend -leaf
        $FilePath = Split-Path $filetosend -Parent
        $bytes = Get-Content $filetosend -Encoding Byte
		$enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
		$FileContent = $enc.GetString($bytes)

		# Body of the request
		# Each parameter is in a new multipart boundary section
		# We don't do much with os/os version/source yet
		$Body = (
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="api_key"',
			"",
			$key,
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="filename"',
			"",
			$fileName,
            "------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="password"',
			"",
			$password,
            "------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="tags"',
			"",
			"LR-SmartResponse",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="os"',
			"",
			"",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="osver"',
			"",
			"",
			"------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="source"',
			"",
			"",

			# This is the file itself
			"------------MULTIPARTBOUNDARY_`$",
			("Content-Disposition: form-data; name=`"sample`"; filename=`"${fileName}`""),
			("Content-Type: `"${fileType}`""),
			"",
			$fileContent,
			"------------MULTIPARTBOUNDARY_`$--",
			""
		) -join "`r`n"

		# Tell TG what the content-type is and what the boundary looks like
		$ContentType = 'multipart/form-data; boundary=----------MULTIPARTBOUNDARY_$'

		$Uri = "https://panacea.threatgrid.com/api/v2/samples"
		try {
			# Call ThreatGRID
			$Response = Invoke-RestMethod -Uri $Uri -Headers $api_headers -method POST -Body $Body -ContentType $ContentType
            Start-Sleep -Seconds 30 #Wait 30 seconds

            Remove-Item $currentfile
            Remove-Item -Path C:\BITS\temp\ -Recurse
		}
		catch {
			write-host "Failed to upload" $FileName "to ThreatGrid"
			#return $null
		}
}
