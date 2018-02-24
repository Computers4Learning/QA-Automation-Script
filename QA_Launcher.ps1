<#QA Launcher
    Launcher written to find, download then launch the latest Quality Assurance Script

    Written by Mitchell Beare 2018
#>

#Declare Functions
Function Write-Console{
    [CmdletBinding()]
    Param ([string]$input)
    $input = $input + "`r`n"
    $Outputtxtbox.Text = $Outputtxtbox.Text += $input
    $QALauncher.Refresh()
}#End Write-Console
Function Test-Network{
        [bool]$connected = $false
        do{
            if(Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet){
                $connected = $true
                }Else{
                Write-Console -input 'No Network Connection was found.'
                Write-Console -input 'Please repair then  try again.'
                }
            }while($connected -eq $false)
}#End Test-Network

#Main
Test-Network
[string]$username = 'currentscript'
[string]$password = 'Passw0rd21'
$secureStringPwd = $password | ConvertTo-SecureString -AsPlainText -Force 
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd
Try{
    Write-Output -InputObject 'Attempting to contact server.'
    New-PSDrive -Name temp -PSProvider FileSystem -Root \\192.168.1.18\currentscript -Credential $creds
}Catch{
    Write-Output -InputObject 'Failed to Contact FileServer to update QA-Script please contact workshop manager.'
}
If(Test-Path -Path temp:\){
    Write-Output -InputObject 'Downloading most recent copy of QA Script'
    Copy-Item -Path 'temp:\*.exe' -Destination "$env:HOMEDRIVE\Users\User\Desktop"
}Else{
    Write-Host 'QA-Script is up to date continuing.'
}

Remove-PSDrive -Name temp
Write-Output -InputObject 'Successfuly downloaded QA Script press any key to continue.'
Pause
Start-Process -FilePath 'C:\Users\User\Desktop\Automated-QA*' -Verb runAs
IF(Get-ScheduledTask | Where-Object TaskName -Match 'Script Removal'){
  Unregister-ScheduledTask -TaskName 'Script Removal' -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute Powershell.exe -Argument "Remove-Item 'C:\Users\User\Desktop\QA_Launcher.exe' -Force"
$setting = New-ScheduledTaskSettingsSet -Priority 5 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -StartWhenAvailable -WakeToRun
$Time = Get-Date
$Time = $Time.AddSeconds(7)
$trigger = New-ScheduledTaskTrigger -At $Time -Once 
$User = "$env:USERDOMAIN\$env:USERNAME"
Register-ScheduledTask -TaskName 'Script Removal' -User $User -Action $action -Trigger $trigger -Settings $setting