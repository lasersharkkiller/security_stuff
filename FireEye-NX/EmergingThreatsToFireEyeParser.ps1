##### Status: Completed #####
#
# Script Author: Ian Norton
# Creation Date: 20190816
#
###PRE-SCRIPT STEPS
###Download Emerging threat rules from https://rules.emergingthreats.net/open/snort-2.9.7.0/emerging.rules.tar.gz
###NOTE replace snort-2.9.7.0 with whatever you are running under the hood
###If on windows use 7zip, right click and extract. Right click the new file and extract again, you will get several rule sets
###Side note, Recommend loading the compromised-ips.txt into your NSM solution
#
###README
###If you are not wiping and replacing rules in your NX's, you must set the value of the next sid EVERY TIME you run this script.
###Otherwise just delete all rules, and run this script as is, then upload the new rules; however any custom rules will need to be replaced as well
###To upload the rules in your NX, log in to the Central Manager as admin, go to IPS / Custom Rules. Ensure Write to Group is on, select your NX group, then upload the modified rules files


#####################
##### Variables #####
#####################
$sid = 85000001
$n = -1


#####################
###### Script #######
#####################
Get-ChildItem C:\Temp\EmergingThreats *.rules -recurse |
    Foreach-Object {

    #$FilePath = "C:\Temp\EmergingThreats"
    [regex]$regex='sid:[0-9]{1,7}'

    (Get-Content ($FilePath+$_.FullName)) | Foreach-Object {
        $sid++ 
        $n++ 
        $replacedcontent = "sid:"+$sid
        $_ -replace $regex, "$replacedcontent"
        } | Set-Content ($FilePath+$_.FullName)
    }
