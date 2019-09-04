##### Status: In Progress #####
#
# Script Author: Ian Norton
# Creation Date: 20190903
#
# This script provides various Search options against ThreatGrid

###ThreatGrid API key
$key = "3m9h9mr5fi0v925k1pbdnv6l52"

###GUI: Choose Domain, IP, or URL Search
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Data Entry Form'
$form.Size = New-Object System.Drawing.Size(600,400)
$form.StartPosition = 'CenterScreen'

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(150,240)
$OKButton.Size = New-Object System.Drawing.Size(150,46)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(300,240)
$CancelButton.Size = New-Object System.Drawing.Size(150,46)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(20,40)
$label.Size = New-Object System.Drawing.Size(560,40)
$label.Text = 'Please make a selection from the list below:'
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.Listbox
$listBox.Location = New-Object System.Drawing.Point(20,80)
$listBox.Size = New-Object System.Drawing.Size(520,160)

$listBox.SelectionMode = 'MultiExtended'

[void] $listBox.Items.Add('Query Domain Against ThreatGrid')
[void] $listBox.Items.Add('Query IP Against ThreatGrid')
[void] $listBox.Items.Add('Query URL Against ThreatGrid')
[void] $listBox.Items.Add('Query Process Against ThreatGrid')
[void] $listBox.Items.Add('Query Hash Against ThreatGrid')
[void] $listBox.Items.Add('Query File Against ThreatGrid')

$listBox.Height = 70
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItems
}
elseif ($result -eq [System.Windows.Forms.DialogResult]::Cancel)
{
    Exit
}

###compare the option chosen and prompt for further input
switch($x)
{
    "Query Domain Against ThreatGrid"{$optionChosen=1;Break}
    "Query IP Against ThreatGrid"{$optionChosen=2;Break}
    "Query URL Against ThreatGrid"{$optionChosen=3;Break}
    "Query Process Against ThreatGrid"{$optionChosen=4;Break}
    "Query Hash Against ThreatGrid"{$optionChosen=5;Break}
    "Query File Against ThreatGrid"{$optionChosen=6;Break}
}


### function for correlating user input and API Query based on first option
function secondGUI {
    param ($value)
        
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Data Entry Form'
    $form.Size = New-Object System.Drawing.Size(600,400)
    $form.StartPosition = 'CenterScreen'

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(150,240)
    $OKButton.Size = New-Object System.Drawing.Size(150,46)
    $OKButton.Text = 'OK'
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(300,240)
    $CancelButton.Size = New-Object System.Drawing.Size(150,46)
    $CancelButton.Text = 'Cancel'
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20,40)
    $label.Size = New-Object System.Drawing.Size(560,40)
    $label.Text = "Please enter the $value you wish to query"
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(20,80)
    $textBox.Size = New-Object System.Drawing.Size(520,40)
    $form.Controls.Add($textBox)

    $form.Topmost = $true

    $form.Add_Shown({$textBox.Select()})
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $y = $textBox.Text
        return $y
    }
    elseif ($result -eq [System.Windows.Forms.DialogResult]::Cancel)
    {
        Exit
    }
}


###Request to ThreatGrid
if ($optionChosen = 1){
    $userInput = secondGUI "Domain"
    $api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?term=domain&q=$userInput&api_key=$key"
}
elseif ($optionChosen = 2){
    $userInput = secondGUI "IP"
    $api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?q=$userInput&api_key=$key"
}
elseif ($optionChosen = 3){
    $userInput = secondGUI "URL"
    $api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?q=$userInput&api_key=$key"
}
elseif ($optionChosen = 4){
    $userInput = secondGUI "Process"
    $api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?term=sample&q=$userInput&api_key=$key"
}
elseif ($optionChosen = 5){
    $userInput = secondGUI "Hash"
    $api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?term=sample&q=$userInput&api_key=$key"
}
elseif ($optionChosen = 6){
    $userInput = secondGUI "File"
    $api_query = "https://panacea.threatgrid.com/api/v2/search/submissions?term=sample&q=$userInput&api_key=$key"
}


###API header variable remains constant for all options
$api_headers = @{
"Authorization"="APIToken $api_token"
"Content-Type"="application/json"
"User-Agent"="PostmanRuntime/7.15.2"
"Accept"="*/*"
"Cache-Control"="no-cache"
"Host"="panacea.threatgrid.com"
"Accept-Encoding"="gzip, deflate"
}

###Actual API Query Invoked; cap results to 100
$agent_response = Invoke-RestMethod -Uri $api_query -Headers $api_headers -Method Get
$total = $agent_response.data.total
if ($total > 100){
    $total = 100
    }

###Output just the Threat Score and SHA1 values for now, and discard null results
Write-Host "ThreatScore: SHA1 Value" `n
for ($n=0; $n -lt $total;$n++){
    if ($agent_response.data[0].items[$n].item.analysis.threat_score){
        Write-Host $agent_response.data[0].items[$n].item.analysis.threat_score ":" $agent_response.data[0].items[$n].item.sha1
        }
}
