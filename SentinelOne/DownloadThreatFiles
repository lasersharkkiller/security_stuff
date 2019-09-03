##### Status: In Progress #####
#
# Script Author: Ian Norton
# Creation Date: 20190726
#
# This script will send a request for S1 to upload blocked files to S1,
# Then it will pull down those blocked files. This script is meant to be
# run on a scheduled task every hour OFF NETWORK.
 
Add-Type -AssemblyName System.Web
 
#####################
##### Variables #####
#####################
#### Getting Time Range #####
$cur_time = Get-Date
$time_to_look_from = $cur_time.AddHours(-5) #Set the number of hours back for query. If on cron job how many hours between runs.
$zulu_time = Get-Date $time_to_look_from.ToUniversalTime().ToString() -Format "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"
$encoded_time = [System.Web.HttpUtility]::UrlEncode($zulu_time)
 
#### API Related ####
$api_Token = "INSERTYOURAPITOKENHERE"
$our_site = "INSERTYOURSITEHERE"
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
        #$To = ("ian.norton@nscorp.com,Muhammad.Varachhia@nscorp.com")
        #$From = "admin@epo.nscorp.com" #origination account for status emails
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
            password = "INFECTED123!"
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
    #$To = ("ian.norton@nscorp.com,Muhammad.Varachhia@nscorp.com")
    #$From = "admin@epo.nscorp.com" #origination account for status emails
    #$SMTPServer = "mailhub.nscorp.com"; #system to process status email
    #$subject = "SentinelOne - Pull Malware Error"
    #$body="Error Title: " + $err_object.errors.title + "`n`n"
    #$body = $body += "Most likely need to update API Key located in script running on malware laptop"
    #Send-MailMessage -SmtpServer $SMTPServer -Subject $subject -Body $body -to $To -From $From
 
    } #end catch
 
#### BUILD LIST OF FILES FROM RESPONSE ####
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
