##### Status: In Progress #####
#
# Script Author: Ian Norton
# Creation Date: 20190910
#
# PowerShell converted scripts from https://github.com/CiscoSecurity/
# Script to submit a file with no password. Replace $key $currentfile and $password

###ThreatGrid API key
$key = "REPLACE-YOUR-KEY-HERE"
$password = "infected"

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

###Define the file being submitted
$currentfile = "C:\bits\2ba14072c68a485d8eb040f8e61347b3-sample.zip"
 
	    # Read the file contents in as a byte array
		$fileName = Split-Path $currentfile -leaf
        $FilePath = Split-Path $currentfile -Parent
        $bytes = Get-Content $currentfile -Encoding Byte
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
			'Content-Disposition: form-data; name="tags"',
			"",
            "------------MULTIPARTBOUNDARY_`$",
			'Content-Disposition: form-data; name="password"',
			"",
			$password,
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
			return $Response.data

            $Response.data
            $sampleId = $Response.data.id
            
            #echo "Sample Submitted to ThreatGrid:" 
		}
		catch {
			write-host "Failed to upload" $FileName "to ThreatGrid"
			return $null
		}
	 else {
        write-host "Fail."
    }
