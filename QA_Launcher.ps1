# XAML Test

#Setup the Model==========================================================================
Function Write-Console{
    [CmdletBinding()]
    Param ([string]$test)
    $test = $test + "`n"
    $WPFOutputtxtbox.Text += $test
}#End Write-Console

Function Test-Network{
        Write-Console -test 'Testing Network Connection'
        [bool]$connected = $false
        do{
            if(Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet){
                Write-Console -test 'Network test successful'
                $connected = $true
                }Else{
                Write-Console -test 'No Network Connection was found.'
                Write-Console -test 'Please repair then  try again.'
                }
            }while($connected -eq $false)
}#End Test-Network

Function Enter-Main {
  Test-Network
  [string]$username = 'currentscript'
  [string]$password = 'Passw0rd21'
  $secureStringPwd = $password | ConvertTo-SecureString -AsPlainText -Force 
  $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd
  Try{
    Write-Console -test 'Attempting to contact server.'
    New-PSDrive -Name temp -PSProvider FileSystem -Root \\192.168.1.18\currentscript -Credential $creds
  }Catch{
    Write-Console -test 'Failed to Contact FileServer to update QA-Script please contact workshop manager.'
  }
  If(Test-Path -Path temp:\){
    Write-Console -test 'Downloading most recent copy of QA Script'
    Copy-Item -Path 'temp:\*.exe' -Destination "$env:HOMEDRIVE\Users\User\Desktop"
  }Else{
    Write-Host 'QA-Script is up to date continuing.'
  }

  Remove-PSDrive -Name temp
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
}

#Setup the  View=============================================================

#ERASE ALL THIS AND PUT XAML BELOW between the @" "@
$inputXML = @"
<Window x:Name="LauncherMain" x:Class="WpfApp1.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:WpfApp1"
        mc:Ignorable="d"
        Title="QALauncher" Height="580" Width="680" Background="#FFECE4E4">
    <Grid Margin="10">
        <TextBox x:Name="Outputtxtbox" HorizontalAlignment="Center" Height="300" Margin="0" IsReadOnly="True" TextWrapping="Wrap" Text="TextBox" VerticalAlignment="Center" Width="400" Background="White" BorderBrush="White" SpellCheck.IsEnabled="True" IsUndoEnabled="False" MaxLines="200" MinLines="11" FontWeight="Medium"/>

    </Grid>
</Window>
"@       
 
$inputXML = $inputXML -replace 'mc:Ignorable="d"','' -replace "x:N",'N'  -replace '^<Win.*', '<Window'
 
[void][Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $inputXML
#Read XAML
 
    $reader=(New-Object System.Xml.XmlNodeReader $xaml)
try{$Form=[Windows.Markup.XamlReader]::Load( $reader )}
catch{Write-Warning "Unable to parse XML, with error: $($Error[0])`n Ensure that there are NO SelectionChanged properties (PowerShell cannot process them)"
    throw}

#Setup the controller=================================================

#Read through XAML and activate components.
$xaml.SelectNodes("//*[@Name]") | ForEach-Object{"trying item $($_.Name)";
    try {Set-Variable -Name "WPF$($_.Name)" -Value $Form.FindName($_.Name) -ErrorAction Stop}
    catch{throw}
    }
 
$WPFOutputtxtbox.Text = "C4L QA Launcher: `n"
$Form.Add_ContentRendered({
    Enter-Main
})




#Show the form
Write-Host $test
$null = $Form.ShowDialog()