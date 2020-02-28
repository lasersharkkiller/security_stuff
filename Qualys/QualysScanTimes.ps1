# Demo code used in blog post https://stuart-clarkson.blogspot.co.uk/2017/01/getting-qualys-asset-scan-information.html
# Created by Stuart Clarkson (17 January 2017)
# Slightly modified to force TLS 1.2 for PS Errors
# This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License.
# https://creativecommons.org/licenses/by-sa/4.0/

# Uses the Qualys API v2
# https://www.qualys.com/docs/qualys-api-v2-user-guide.pdf


# Set your Qualys username & password here
$QualysUsername = 'user'
$QualysPassword = 'password'

# Set your Qualys Platform domain name here
#Platform identification: https://www.qualys.com/platform-identification/
$QualysPlatform = 'qualysguard.qg2.apps.qualys.com'


# This section forms a string with the username & password in the 'Basic Authentication' standard format (RFC 1945)
# See https://tools.ietf.org/html/rfc1945#section-11.1 & https://en.wikipedia.org/wiki/Basic_access_authentication
$BasicAuthString = [System.text.Encoding]::UTF8.GetBytes("$QualysUsername`:$QualysPassword")
$BasicAuthBase64Encoded = [System.Convert]::ToBase64String($BasicAuthString)
$BasicAuthFormedCredential = "Basic $BasicAuthBase64Encoded"


# Form a key/value hashtable with the HTTP headers we'll be sending in the HTTP request
$HttpHeaders = @{'Authorization' = $BasicAuthFormedCredential; 
                 'X-Requested-With'='PowerShell Script'} # Qualys API documentation required the X-Requested-With header be set to something


# Qualys QID 45038 is the QID where host scan time information is contained
$qualys_scan_qid = 45038

# Limit the number of hosts to return
$TruncationLimit = 500

# Set the URL
# Output format is set to XML so XML data is returned
# show_igs is set to 1 as we want to show the information gathered
$URL = "https://$QualysPlatform/api/2.0/fo/asset/host/vm/detection/?action=list&qids=$qualys_scan_qid&truncation_limit=$TruncationLimit&output_format=XML&show_igs=1"

#Run the following for errors regarding unexpected error occurring on send or error creating SSL/TLS channel
#Source: https://evotec.xyz/invoke-restmethod-the-underlying-connection-was-closed-an-unexpected-error-occurred-on-a-send-while-connecting-graph-api/
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Invoke-WebRequest sends the HTTP request and the returned data is stored in $response
# If going through a proxy, '-Proxy, -ProxyUseDefaultCredentials or -ProxyCredential may need to be set too
$HttpResponse = Invoke-WebRequest -Uri $URL -Headers $HttpHeaders

# The content of the HTTP response is in the Content property of the $HTTPResponse.  Form this as an XML object
$QualysXMLResponse = [xml]$HttpResponse.Content

# Check that the Qualys reponse contains a HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST.HOST element
if ($QualysXMLResponse.HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST.HOST)
{
    # $AllHosts will contain the host data for all the hosts returned by the Qualys API
    $AllHosts = $QualysXMLResponse.HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST.HOST

    # $HostAssets will be the array of PowerShell objects representing the information for each host
    $HostAssets = @()

    # Lets loop round each host in AllHosts
    foreach($IndividualHost in $AllHosts)
    {
        # Quick method to create a custom PowerShell object with specific attributes
        $asset = "" | select Name, IP, LastScanDate, LastScanDuration

        # Set the attributes to be the values of the XML
        $asset.Name = $IndividualHost.dns.InnerText
        $asset.IP = $IndividualHost.IP

        # XML attribute LAST_SCAN_DATETIME contains the date represented in string form
        # We form a PowerShell DateTime object from it here
        $asset.LastScanDate = [DateTime]$IndividualHost.LAST_SCAN_DATETIME

        # Scan duration field may not exist if the scan isn't a recent one.  Wrap a try/catch block around it 
        try
        {
            # LAST_VM_SCANNED_DURATION is an integer of the number of seconds the scan took.
            # Form a PowerShell TimeSpan object for it
            # https://technet.microsoft.com/en-us/library/ee176916.aspx
            $asset.LastScanDuration = New-TimeSpan -Seconds $IndividualHost.LAST_VM_SCANNED_DURATION
        }
        catch
        {
            Write-Verbose -Message ("No scan duration value for "+$asset.Name)
        }
        
        # Add the asset object to the HostAssets array
        $HostAssets+=$asset

        # Write verbose details
        Write-Verbose -Message ("Formed "+$asset.Name+" information")
    }
}
else
{
    Write-Warning -Message "Response from Qualys wasn't what we expected:-"
    $response.Content
}

# $HostAssets is now a fully formed array of PowerShell Objects
Write-Output $HostAssets
