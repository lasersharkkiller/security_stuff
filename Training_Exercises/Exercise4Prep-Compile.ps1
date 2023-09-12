#############################################################
#########################Exercise #4#########################
#############################################################
# Compile to exe:
#Install-Module ps2exe
#Invoke-PS2EXE thisScript.ps1 svch0st.exe

#Infinite loop of dad jokes every 5 minutes; to be compiled
for(;;){
#Invoke Dad Joke
Invoke-WebRequest -Uri "https://icanhazdadjoke.com" -Headers @{accept="application/json"} | Select -ExpandProperty Content | ConvertFrom-Json | Select -ExpandProperty Joke

#Sleep
Start-Sleep -Seconds 300
}
