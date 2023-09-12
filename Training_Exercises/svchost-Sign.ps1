#############################################################
#########################Exercise #4#########################
#############################################################

# Compile to exe:
#Install-Module ps2exe
#Invoke-PS2EXE thisScript.ps1 svch0st.exe

<#
#The following is to sign the exe after
$params = @{
    Type = 'CodeSigningCert'
    DnsName = 'Microsoft Corporation'
    Subject = 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    CertStoreLocation = 'Cert:\LocalMachine\My'
}
New-SelfSignedCertificate @params
Get-ChildItem Cert:\LocalMachine\My
$cert = (Get-ChildItem -Path Cert:\LocalMachine\My -CodeSigningCert)[0]
#Set-AuthenticodeSignature -FilePath apt170Signed.exe -Certificate $cert
#>

#Infinite loop of dad jokes every 5 minutes; to be compiled
for(;;){
#Dad Joke
Invoke-WebRequest -Uri "https://icanhazdadjoke.com" -Headers @{accept="application/json"} | Select -ExpandProperty Content | ConvertFrom-Json | Select -ExpandProperty Joke

#Sleep
Start-Sleep -Seconds 300
}
