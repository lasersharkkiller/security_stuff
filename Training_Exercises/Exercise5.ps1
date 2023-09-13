#############################################################
##########################Exercise #5########################
#############################################################

#Array of core services, slightly off for Hamming Analysis
$strarry = @("smsss.exe", "winninit.exe", "runtimebr0ker.exe","taskh0stw.exe","winl0gon.exe","cssrss.exe","servic3s.exe","svch0st.exe","1saiso.exe","1sass.exe","expl0rer.exe")

$pickRandom = Get-Random -Minimum 0 -Maximum 10

$Exercise5exe = $strarry[$pickRandom]

#This assume apt170Unsigned.exe is in the same folder as your script
Copy-Item apt170Unsigned.exe $strarry[$pickRandom]
#Run
Start-Sleep -Milliseconds 3000
Invoke-Expression -Command ".\$($Exercise5exe)"
