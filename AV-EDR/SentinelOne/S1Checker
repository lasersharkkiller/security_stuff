##### Status: COMPLETE #####
#
# Script Author: Name Omitted but not me
# Start Date: 20190626
#
# This script queries the SentinelOne API for the propertiess of a single system.
# It is meant to be used as a quick check to see if the system has SentinelOne.

#####################
##### Variables #####
#####################

#### Check for command line argument, prompt if none. ####
if (!$args[0])
{
    $computerName = "blank"
    $computerName = Read-Host "Enter name of computer to Query SentinelOne API for"

}
else 
{
    $computerName = $args[0]

}# end if else

#### API Related ####
$api_Token = "changeme"
$our_site = "usea1-changeme"
$agent_summary = "https://$our_site.sentinelone.net/web/api/v2.0/private/agents/summary"
$agent_data = "https://$our_site.sentinelone.net/web/api/v2.0/agents"

########################
##### Main Program #####
########################

#
##### Get AGENT DATA #####
#

##### CONFIGURE HTTP HEADER FOR THE API CALL #####
$api_headers = @{
"Authorization"="APIToken $api_token"
"Content-Type"="application/json"
}

#### CONFIGURE HTTP QUERY STRING/BODY FOR THE API CALL ####
$cursor = $agent_response.pagination.nextCursor
$api_query = @{
"isDecommissioned"="False"
"computerName"="$computerName"
}

#### QUERY THE API ####
try {
        $agent_response = Invoke-RestMethod -Uri $agent_data -Headers $api_headers -Body $api_query -Method Get 

    } #end try

catch { 
        
        Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
        Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
        
        $err_object = $_ | ConvertFrom-Json
        Write-Host "Error Title:" $err_object.errors.title
        $err_object.errors.title | Out-File -FilePath $txt_file

        ### SEND EMAIL WITH ERROR INFO ###
        $To = ("email@domain.com")
        $From = "admin@domain.com" #origination account for status emails
        $SMTPServer = "mailhub.domain.com"; #system to process status email
        $subject = "SentinelOne - GetS1AgentsList Error"
        $body="Error Title: " + $err_object.errors.title + "`n`n"
        $body = $body += "Update API Key located in script at: `n`n \\location"
        Send-MailMessage -SmtpServer $SMTPServer -Subject $subject -Body $body -to $To -From $From

        } #end catch


#### IF COMPUTER NOT FOUND ####
if ($agent_response.pagination.totalItems -eq 0)
{

    Write-Host `n
    Write-Host $computerName "was not found"
    
}

#### OTHERWISE DISPLAY RESULTS ####
else
{
    Write-Host `n
    Write-Host "Response Information..." `n
    Write-Host "Total found: " $agent_response.pagination.totalItems
    Write-Host "Computer Name: " $agent_response.data.computerName
    Write-Host "Agent Version: " $agent_response.data.agentVersion
    Write-Host "Enrollment Date: " $agent_response.data.createdAt
    Write-Host "IPv4 Address(es): " $agent_response.data.networkinterfaces.inet
    
}
