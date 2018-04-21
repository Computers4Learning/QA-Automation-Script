<# Mark: About Script
    C4L Quality Assurance Script

    The purpose of this script is to automate the process of quality checking 
    refurbished machines on the computers 4 learning project.

    Written By Mitchell Beare
    2018
#>

#Mark: Iniatialise
$ErrorActionPreference = 'Inquire'

#Mark: API Connections
Function Connect-NativeHelperType{
    $nativeHelperTypeDefinition =
    @'
    using System;
    using System.Runtime.InteropServices;

    public static class NativeHelper
        {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        public static bool SetForeground(IntPtr windowHandle)
        {
           return NativeHelper.SetForegroundWindow(windowHandle);
        }

    }
'@
  if(-not ([Management.Automation.PSTypeName] 'NativeHelper').Type)
    {
        Add-Type -TypeDefinition $nativeHelperTypeDefinition
    }
}#End Connect-NativeHelperType
Function Connect-AudoController{
    [CmdletBinding()]
    Param()
    Add-Type -TypeDefinition @'
    using System.Runtime.InteropServices;
    [Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IAudioEndpointVolume{
        // f(), g(), ... are unused COM method slots. Define these if you care
        int f(); int g(); int h(); int i();
      int SetMasterVolumeLevelScalar(float fLevel, System.Guid pguidEventContext);
      int j();
      int GetMasterVolumeLevelScalar(out float pfLevel);
      int k(); int l(); int m(); int n();
      int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, System.Guid pguidEventContext);
      int GetMute(out bool pbMute);
    }
    [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMMDevice{
        int Activate(ref System.Guid id, int clsCtx, int activationParams, out IAudioEndpointVolume aev);
    }
    [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IMMDeviceEnumerator{
        int f(); // Unused
        int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);
    }
    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }
    public class Audio{
        static IAudioEndpointVolume Vol(){
            var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;
            IMMDevice dev = null;
            Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(/*eRender*/ 0, /*eMultimedia*/ 1, out dev));
            IAudioEndpointVolume epv = null;
            var epvid = typeof(IAudioEndpointVolume).GUID;
            Marshal.ThrowExceptionForHR(dev.Activate(ref epvid, /*CLSCTX_ALL*/ 23, 0, out epv));
            return epv;
        }
        public static float Volume{
            get { float v = -1; Marshal.ThrowExceptionForHR(Vol().GetMasterVolumeLevelScalar(out v)); return v; }
            set { Marshal.ThrowExceptionForHR(Vol().SetMasterVolumeLevelScalar(value, System.Guid.Empty)); }
        }
    public static bool Mute
    {
        get { bool mute; Marshal.ThrowExceptionForHR(Vol().GetMute(out mute)); return mute; }
        set { Marshal.ThrowExceptionForHR(Vol().SetMute(value, System.Guid.Empty)); }
    }
}
'@
}#End Connect-AudoController
Connect-NativeHelperType
Connect-AudoController

#Mark: Functions

Function Check-Key{
  [CmdletBinding()]
  Param([String]$key)
  if($key -match '^([a-zA-Z0-9]{5}-?){5}' -and $key.Length -eq 29){
    Return $true
  }Else{
    Return $false
  }
}
Function Activate-Windows{
  $finished = $false
  [string]$response = Read-Host -Prompt "Do you need to activate Windows? `n Y/N"
  if($response -eq 'Y' -Or $response -eq 'y'){
    Do{
      $name = $env:COMPUTERNAME
      $key = Read-Host -Prompt "Please enter Windows activation key in form XXXX-XXXX-XXXX-XXXX `n"
      $key = $key.Trim()
      if(Check-key -key $key){
        Write-Output -InputObject 'Attempting to activte windows.'
        $service = Get-wmiobject -class SoftwareLicensingService -ComputerName $name 
        $null = $service.InstallProductKey($key)
        $null = $service.RefreshLicenseStatus()
        $finished = $true
      }Else{
        Write-Warning -Message 'Key was typed incorrectly please try again.'
      
      }
    }While($finished = $false )
  }
}#End Activate-Windows
Function Test-WinActivation{
    $status = Get-Ciminstance -ClassName SoftwareLicensingProduct | Where-Object{$_.PartialProductKey} | Select-Object -ExpandProperty LicenseStatus
    if($status -eq 1){
        Return $true
    }Else{
        Return $false
    }
}#End Test-WinActivation
Function Activate-Office{
  $finished = $false
  [string]$response = Read-Host -Prompt "Do you need to activate Office? `n Y/N"
  if($response -eq 'Y' -Or $response -eq 'y'){
    $name = $env:COMPUTERNAME
    $key = Read-Host -Prompt "Please enter Office activation key in form XXXX-XXXX-XXXX-XXXX `n"
    $key = $key.Trim()
    if(Check-Key -key $key){
      Write-Output -InputObject 'Attempting to activte Office.'
      $service = Get-wmiobject -class OfficeSoftwareProtectionService -ComputerName $name 
      $null = $service.InstallProductKey($key)
      cscript 'C:\Program Files\Microsoft Office\Office14\OSPP.vbs' /act
      $finished = $true
    }Else{
      Write-Error -Message 'Key as typed incorrectly please try again.'

    }
  }
}#End Activate-Office
Function Test-OfficeActivation{
C:\Windows\System32\cscript.exe 'C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS' /dstatus | Out-File -FilePath $env:temp\actstat.txt
 
$ActivationStatus = $($Things = $(Get-Content -Path $env:temp\actstat.txt -ReadCount -raw) `
                            -replace ':'," =" `
                            -split "---------------------------------------" `
                            -notmatch "---Processing--------------------------" `
                            -notmatch "---Exiting-----------------------------"
                       $Things | ForEach-Object {
                       $Props = ConvertFrom-StringData -StringData ($_ -replace '\n-\s+')
                       New-Object -TypeName psobject -Property $Props  | Select-Object -Property "SKU ID", "LICENSE NAME", "LICENSE DESCRIPTION", "LICENSE STATUS"
        })
 
$Var = "Office Activated "
for ($i=0; $i -le $ActivationStatus.Count-2; $i++) {
    if ($ActivationStatus[$i]."LICENSE STATUS" -eq "---LICENSED---") {
        $Var = $Var + "OK "
        }
 
    else {
        $Var = $Var + "Bad "
        }
        }
 
If ($Var -like "*Bad*") {
 
    Write-Warning -Message "Office Not Activated"
}
else
{
    Write-Output -InputObject "Office Activated"
}



}#End Test-OfficeActivation
Function Read-ConfigFile {
  #This function reads the server side config file and loads variables into memory for use. 

    #Create server connect creds
    $username = 'currentscript'
    $password = 'Passw0rd21'
    $secureStringPwd = $password | ConvertTo-SecureString -AsPlainText -Force 
    $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd

    #Create a drive with the FileServer
    Try{
        $null = New-PSDrive -Name temp -PSProvider FileSystem -Root \\192.168.1.18\currentscript -Credential $creds
    }Catch{
        Write-Output -InputObject 'Failed to Contact FileServer to update QA-Script please contact workshop manager.'
    }

    #Load Configuration XML
    if(Test-Path -Path temp:\){
        [xml]$Script:XmlDocument = Get-Content -Path temp:\Script_Config.xml
    }Else{
    Write-Error -Message 'Warning Failed to load config some functions may fail.'
    }

    #Cleanup
     Remove-PSDrive -Name temp
}#End Read-ConfigFile
Function Get-Software {
    Param([Parameter(Mandatory=$true,HelpMessage='A Comma Seperated list of Softwares to search for.')]
    [string[]]$installedsoftware)
    
    Foreach($app in $installedsoftware){
        Write-Output -InputObject "Checking 64bit registry for $app."
        $64bit = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object -Property DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | 
        Out-String
        if ([string]::IsNullOrEmpty($64bit )){
            Write-Output -InputObject "Checking 32bit registry for $app."
            $32bit = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
            Select-Object -Property DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | 
            Out-String
            $32bit = $32bit.TrimEnd()
            Write-log -text $32bit
        }elseif([string]::IsNullOrEmpty($32bit)) {
            Write-log -text "$app Could not be found"
        }else{
            $64bit = $64bit.TrimEnd()
            Write-log -text $64bit
        }
    }
}#End Get-Software
Function Test-DeviceDriver{
    #Checks for devices whose ConfigManagerErrorCode value is greater than 0, i.e has a problem device.
    $missingdrivers = Get-ciminstance -Class Win32_PnpEntity -Namespace Root\CIMV2 | 
    Where-Object {$_.ConfigManagerErrorCode -gt 0 } |Select-Object -Property Name,DeviceID,ConfigManagerErrorCode | Out-String

    if($null -eq $missingdrivers){
      Write-log -text ('No Device Drivers are Missing on this machine.')
    }else{
      ForEach($missingdrive in $missingdrivers){
      Write-log -text ("The drivers were not found for `n $missingdrive")
      }
    }
}#End Test-Drivers
Function Expand-Drive{
        if(Test-Path -Path C:\){
          $maxsize = (Get-PartitionSupportedSize -DriveLetter C).sizemax
          $drivesize = (Get-Partition -DriveLetter C).size
          if($drivesize -eq $maxsize){
            Write-Output -InputObject "$env:HOMEDRIVE\ Drive is already at maximum size"
          }Else{
            Write-Output -InputObject "$env:HOMEDRIVE\ Drive does not currently fill the Harddrive Expanding..."
            Resize-Partition -DriveLetter C -Size $maxsize
            Write-Output -InputObject "Successfully expanded 'C:\' Drive."
          }
          $maxsize = $maxsize/1024/1024/1024
          $maxsize = [Math]::Round($maxsize)
          Write-log -text "C:\ is $($maxsize)GB"
        }Else{
          Write-Warning -Message 'Failed to find C:\ please check for drive errors.'
          Write-Log -text 'Failed to find C:\ please check for drive errors. '
        }
}#End Expand-Drive
Function Open-InternetExplorer{
    param ([Parameter(Mandatory=$true,HelpMessage='Url Internet Explorer opens to.')]
           [string]$videourl)
  $IE = new-object -ComObject internetexplorer.application
  $IE.navigate2($videourl)
  $IE.visible=$true
  [NativeHelper]::SetForeground($IE.HWND)
  $input = Read-Host -Prompt 'Was Audio heard Y/N'
  $check = $false
  Do{
    if($input -eq 'Y' -or $input -eq 'y'){
      Write-Log -text 'Audio is functioning correctly.'
      $check = $true
    }Elseif($input -eq 'N' -or $input -eq 'n'){
      $script:failedQA = $true
      Write-Log -text 'Audio failed to be heard please check speakers and audio drivers.'
      $check = $true
    }Else{
      Write-Log -text 'Invalid input detected'
    }
  }While($check -eq $false)
  
}#End Start-Video
Function New-LogFile{
    # File path for QA_Report
    $script:reportFilePath = "$env:Public\Desktop\$($env:computername)-QA_Report.txt"
    
    #Populate System information as variables
    [string]$Model = WMIC ComputerSystem Get Model | Out-String
    $Model = $Model.Substring(5)
    $Model = $Model.Trim()
    [string]$Manufacturer = WMIC ComputerSystem Get Manufacturer | Out-String
    $Manufacturer = $Manufacturer.Substring(12)
    $Manufacturer = $Manufacturer.Trim()

    #Fetch date report was run
    $today = Get-Date

  # Delete file if it already exists
  If (Test-Path -Path $reportFilePath) {
    Remove-Item -Path $reportFilePath
  }

  #Format report and print strings.
  Add-Content -Path $reportFilePath -Value 'Computer Quality Assurance script by Mitchell Beare.'
  Add-Content -Path $reportFilePath -Value "Report Created On: $today`r"
  Add-Content -Path $reportFilePath -Value "QA Report For Computer: $env:computername`r`n"
  Add-Content -Path $reportFilePath -Value "==============================================================================`r`n"
  Add-Content -Path $reportFilePath -Value "System Brand and Model: $Manufacturer $Model"
}#End New-LogFile
Function Write-Log {
  [CmdletBinding()]
  Param([string]$text)
  Add-Content -Path $reportFilePath -Value "`n$($text)"
  
}#End Write-Log
Function Get-RAM{
    try{
      $ram = Get-Ciminstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum |Select-Object -ExpandProperty Sum 
      }catch{
        Write-Warning -Message 'Failed to Retrieve RAM, Please check for fault.'
        Write-Log -text 'Failed to Retrieve RAM, please check for fault.'
      }
    $ram = $ram/1024/1024/1024
    $ram = [Math]::Round($ram)
    Write-log -text "There is $($ram)GB of RAM installed on this machine `n"
}#End Get-Ram
Function Test-Keyboard{
  $teststring ='The quick brown fox jumps over the lazy dog. 1234567890'
  $exit = $false
  Do{
    Write-Output -InputObject 'Please type the following exactly as it appears:'
    $testinput = Read-Host -Prompt "$teststring"
    if ($teststring -eq $testinput){
      Write-Output -InputObject 'Keyboard test was successful continuing'
      Write-log -text 'Keyboard test was successful'
      $exit = $true
    }else{
      Write-Output -InputObject ' '
      Write-Output -InputObject "Keyboard test failed you typed: `n$testinput"
      $continue = Read-Host -Prompt 'Would you like to try again? Y/N'
      if($continue -eq 'n' -or $continue -eq 'N'){
        $script:failedQA = $true
        $script:failreason = 'Keyboard test Failed.'
        Write-Log -text 'Keyboard test failed'
        $exit = $true
      }
    }
  }While($exit -eq $false)
}#End Test-Keyboard
Function Start-CCleaner {
    param([Parameter(Mandatory=$true,HelpMessage='Switch to control whether CC Cleaner is silent or not.')]
    [int]$m)
    if($m -eq 0){
        Write-Output -InputObject 'Starting CCleaner quietly and running'
        Try{
            Start-Process -FilePath CCleaner.exe -ArgumentList /AUTO
            Write-log -text ('CCleaner has run and cleaned the machine.')
            }Catch{
            Write-log -text ('CCleaner was not found or failed to launch.')
        }
    }else{
        Try{
            Start-Process -FilePath CCleaner.exe -ArgumentList /REGISTRY
            Write-log -text ('CCleaner has been opened to perform a registry clean.')
        }Catch{
            Write-log -text ('CCleaner was not found or failed to launch.')
     }
  }
}#End Start-CCleaner
Function Set-ComputerIcon{
  #Registry key path 
  $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' 
  #Property name 
  $name = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' 
  #check if the property exists 
  $item = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue 
  if($item) 
  { 
    #set property value 
    Set-ItemProperty  -Path $path -name $name -Value 0  
  } 
  Else 
  { 
    #create a new property 
    New-ItemProperty -Path $path -Name $name -Value 0 -PropertyType DWORD > $null
    & "$env:windir\system32\rundll32.exe" USER32.DLL,UpdatePerUserSystemParameters 1, True
  } 
}#End Set-ComputerIcon
Function Set-ManufacturerInfo {

    $registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
    [string]$logo = $XmlDocument.Variables.CompanyInfo.Logo
    [string]$manufacturer = $XmlDocument.Variables.CompanyInfo.Manufacturer
    [string]$supportphone = $XmlDocument.Variables.CompanyInfo.SupportPhone
    [string]$supporturl = $XmlDocument.Variables.CompanyInfo.SupportURL.InnerText


    If(!(Test-Path -Path $registryPath))

      {
        New-Item -Path $registryPath -Force > $null

        New-ItemProperty -Path $registryPath -Name Logo -Value $logo -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name Manufacturer -Value $manufacturer -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name SupportPhone -Value $supportphone -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name SupportURL -Value $supporturl -PropertyType String -Force > $null
        
      } Else {

        New-ItemProperty -Path $registryPath -Name Logo -Value $logo -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name Manufacturer -Value $manufacturer -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name SupportPhone -Value $supportphone -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name SupportURL -Value $supporturl -PropertyType String -Force > $null
        }
} #End Set-ManufacturerInfo
Function Send-Report{
    $username = 'qa-report'
    $password = 'Passw0rd21'
    $secureStringPwd = $password | ConvertTo-SecureString -AsPlainText -Force 
    $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd
    Try{
        if(-not(Get-PSDrive | Where-Object Name -match temp)){
          $null = New-PSDrive -Name temp -PSProvider FileSystem -Root \\192.168.1.18\qa-report -Credential $creds
        }
        Copy-Item -Path $reportFilePath -Destination temp:\
        Remove-PSDrive -Name temp
    }Catch{
        Write-Error -InputObject 'Failed to Contact Server to save QA-Report please contact workshop manager.'
    }
}#End Send-Report
Function Test-Network{
        [string]$script:fileserver = '192.168.1.18'
        [bool]$connected = $false
        do{
            if(Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet){
                $connected = $true
                }Else{
                Write-Output -InputObject 'There is no network connection please fix.'
                Write-Output -InputObject 'Before continuing with QA'
                Read-Host -Prompt 'Press any key to try again:'
                }
            }while($connected -eq $false)
            if($connected = $true){
            Write-Output -InputObject 'Checking for C4L Fileserver'
              if(Test-Connection -ComputerName 192.168.1.18 -Count 1 -Quiet){
                Write-Output -InputObject "Successfully connected to server `n"
              }Else{
                $fileserver = Read-Host -Prompt "Fileserver not found at $fileserver`r`nPlease Enter server ip"
              
              }
            }
            
            
}#End Test-Network

#Main ================================================================================
#Remove-Item 'C:\Users\User\Desktop\QA_Launcher.exe' -Force #Enable if QA launcher no longer self deletes
Test-Network

#Configure Variables
Read-ConfigFile
[string]$videourl = $XmlDocument.Variables.videourl.InnerText
[string[]]$installedsoftware = @()
foreach ($thing in $XmlDocument.Variables.installedsoftware.is)
{
    $installedsoftware += $thing
}
[bool]$script:failedQA = $false

#Configure required Modules
$sourceNugetExe = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe'
$targetNugetExe = "$rootPath\nuget.exe"
Invoke-WebRequest -Uri $sourceNugetExe -OutFile $targetNugetExe
Set-Alias -Name nuget -Value $targetNugetExe -Scope Global

#Test for used librarys and install if not found
If(Get-Module -ListAvailable -Name PowerShellGet){
    Write-Output -InputObject 'PowershellGet Configured'
}Else {
    Write-Output -InputObject 'Setting up Powershell Get'
    Install-Module -Name PowershellGet -Force
}#End Installing PowershellGet Module
if(Get-Module -ListAvailable -Name PowerShellGet){
    Write-Output -InputObject 'WindowsUpdates Connected'
}Else{
    Write-Output -InputObject 'Connecting to Windows Updates'
    Install-Module -Name PSWindowsUpdate -Force
}#End Installing PSWindowsUpdate

#Open a new session to run windows updates
Write-Output -InputObject "Starting Windows Updates in a new windows.`n"
Start-Process -FilePath Powershell.exe -ArgumentList {Get-Command -module PSWindowsUpdate;
    Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d;
    Get-WUInstall -MicrosoftUpdate -AcceptAll -IgnoreReboot -Verbose}

#Create and format QA Report
Write-Output -InputObject "Creating Report Log `n"
New-LogFile

Write-Output -InputObject 'Retrieving drives and expanding.'
Expand-Drive

Write-Output -InputObject 'Retrieving Installed Physical Memory.'
Get-RAM
Start-CCleaner -m 0

Write-Output -InputObject 'Configuring OEM Information.'
Set-ManufacturerInfo
Set-ComputerIcon

Write-Output -InputObject 'Contacting Registry and checking for Software'
Get-Software -installedsoftware $installedsoftware

Write-Output -InputObject 'Begginning Keyboard Test.'
Test-Keyboard
Write-Output -InputObject 'Setting Volume to maximum and testing'
Try{
    [audio]::Mute = $false 
    [audio]::Volume = 0.8
}Catch{
    Write-log -text 'No Audio Device could be found'
    Write-Error -Message 'No Audio Device could be found'
}
Open-InternetExplorer -videourl $videourl
Start-CCleaner -m 1
Write-Output -InputObject 'Please wait for windows updates to finish before checking for device drivers.'
Read-Host -Prompt 'Press any key to continue.'
#Wait-Job -Id $j1.Id
Write-Output -InputObject 'Checking for Missing Device Drivers'
Test-DeviceDriver

if($script:failedQA -ne $true){
  Activate-Windows
  if(Test-WinActivation){
    Write-Output -InputObject 'Windows successfully activated.'
    Write-Log -text 'Windows is successfully activated.'
  }Else{
    Write-Output -InputObject 'Windows failed to automatically activate, please activate manually'
    Write-Log -text 'Windows failed to automatically activated, promtped QA technician to activate.'
    Start-Process -FilePath ms-settings:activation
  }
  Activate-Office
}

#Mark: Finalise
Write-Log -text 'QA Script finished sending copy of report to server aqnd rebooting machine.'

Write-Output -InputObject 'Sending a copy of QA-Report to the server.'
Try{
  Send-Report
  Write-Output -InputObject 'Successfully send QA-Report to server.'
}
Catch{
  Write-Warning -Message 'Failed to send QA-Report to server.'
  }
Read-Host -Prompt 'QA Complete Computer will now Restart.'

#Self Removal, must always be last line.
$action = New-ScheduledTaskAction -Execute Powershell.exe -Argument "Remove-Item 'C:\Users\User\Desktop\Automated-QA*' -Force"
$setting = New-ScheduledTaskSettingsSet -Priority 5 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -StartWhenAvailable -WakeToRun
$Time = Get-Date
$Time = $Time.AddSeconds(7)
$trigger = New-ScheduledTaskTrigger -At $Time -Once 
$User = "$env:USERDOMAIN\$env:USERNAME"
Register-ScheduledTask -TaskName 'Script Removal' -User $User -Action $action -Trigger $trigger -Settings $setting
Restart-Computer -Force