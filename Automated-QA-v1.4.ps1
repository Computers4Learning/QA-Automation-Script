<# Mark: About Script
    C4L Quality Assurance Script

    The purpose of this script is to automate the process of quality checking 
    refurbished machines on the computers 4 learning project.

    Written By Mitchell Beare
    2017
#>

#Mark: Iniatialise
$ErrorActionPreference = 'Inquire'

#Mark: Configuration Variables
[string]$videourl = 'https://www.youtube.com/watch?v=nn2FB1P_Mn8'
[string[]]$installedsoftware = ('Panda','VLC','Firefox','Adobe Acrobat Reader')
[bool]$failedQA = $false

#Mark: API Connections
Function Connect-NativeHelperType{
    $nativeHelperTypeDefinition =
    @"
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
"@
if(-not ([System.Management.Automation.PSTypeName] "NativeHelper").Type)
    {
        Add-Type -TypeDefinition $nativeHelperTypeDefinition
    }
}#End Connect-NativeHelperType
Function Connect-AudioControls{
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
}#End Connect-AudioControls
Connect-NativeHelperType
Connect-AudioControls

#Mark: Functions
Function Get-Software {
    Param([Parameter(Mandatory=$true)]
    [string[]]$installedsoftware)
    
    Foreach($app in $installedsoftware){
        Write-Output -InputObject "Checking 64bit registry for $app."
        $64bit = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object -Property DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | 
        Out-String
        if ($64bit -eq ''){
            Write-Output -InputObject "Checking 32bit registry for $app."
            $32bit = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
            Select-Object -Property DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | 
            Out-String
            Write-Log -text $32bit
        }elseif($32bit -eq '') {
            Write-Log -text "$app Could not be found"
        }else{
            Write-Log -text $64bit
        }
    }
}#End Get-Software
Function Test-DeviceDrivers{
    #Checks for devices whose ConfigManagerErrorCode value is greater than 0, i.e has a problem device.
    $missingdrivers = Get-ciminstance -Class Win32_PnpEntity -Namespace Root\CIMV2 | 
    Where-Object {$_.ConfigManagerErrorCode -gt 0 } |Select-Object -Property Name,DeviceID,ConfigManagerErrorCode | Out-String

    if($missingdrivers -eq $null){
      Write-Log -text ('No Device Drivers are Missing on this machine.')
    }else{
      ForEach($missingdrive in $missingdrivers){
      Write-Log -text ("The drivers were not found for `n $missingdrive")
      }
    }
}#End Test-Drivers
Function Expand-Drives{
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
        Write-Log -text "C:\ is $($maxsize)GB"
}#End Expand-Drives
Function Open-InternetExplorer{
    param ([Parameter(Mandatory=$true)]
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
      $failedQA = $true
      Write-Log -text 'Audio failed to be heard please check speakers and audio drivers.'
      $check = $true
    }Else{
      Write-Log -text 'Invalid input detected'
    }
  }While($check -eq $false)
  
}#End Start-Video
Function New-LogFile{
    ## File path for QA_Report
    $script:reportFilePath = "$env:Public\Desktop\$($env:computername)-QA_Report.txt"
    [string]$Model = WMIC ComputerSystem Get Model | Out-String
    $Model = $Model.Substring(5)
    $Model = $Model.Trim()
    [string]$Manufacturer = WMIC ComputerSystem Get Manufacturer | Out-String
    $Manufacturer = $Manufacturer.Substring(12)
    $Manufacturer = $Manufacturer.Trim()


  $today = Get-Date

  ## Delete file if it already exists
  If (Test-Path -Path $reportFilePath) {
    Remove-Item -Path $reportFilePath
  }

  Add-Content -Path $reportFilePath -Value "QA Report For Computer: $env:computername`r`n"
  Add-Content -Path $reportFilePath -Value "Report Created On: $today`r"
  Add-Content -Path $reportFilePath -Value "==============================================================================`r`n"
  Add-Content -Path $reportFilePath -Value "System Brand and Model: $Manufacturer $Model"
}#End New-LogFile
Function Write-Log {
  Param([string]$text)
  Add-Content -Path $reportFilePath -Value "`n$($text)"
  
}#End Write-Log
Function Get-RAM{
    $ram = Get-Ciminstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum |Select-Object -ExpandProperty Sum 
    $ram = $ram/1024/1024/1024
    $ram = [Math]::Round($ram)
    Write-Log -text "There is $($ram)GB of RAM installed on this machine `n"
}#End Get-Ram
Function Test-Keyboard{
  $teststring ='The quick brown fox jumps over the lazy dog. 1234567890'
  $exit = $false
  Do{
    Write-Output -InputObject 'Please type the following exactly as it appears:'
    $testinput = Read-Host -Prompt "$teststring"
    if ($teststring -eq $testinput){
      Write-Output -InputObject 'Keyboard test was successful continuing'
      Write-Log -text 'Keyboard test was successful'
      $exit = $true
    }else{
      Write-Output " "
      Write-Output -InputObject "Keyboard test failed you typed: `n$testinput"
      $continue = Read-Host -Prompt 'Would you like to try again? Y/N'
      if($continue -eq 'n' -or $continue -eq 'N'){
        $failedQA = $true
        $FailReason = "Keyboard test Failed"
        Write-Log -text 'Keyboard test failed'
        $exit = $true
      }
    }
  }While($exit -eq $false)
}#End Test-Keyboard
Function Start-CCleaner {
    param([Parameter(Mandatory=$true)]
    [int]$m)
    if($m -eq 0){
        Write-Output -InputObject 'Starting CCleaner quietly and running'
        Try{
            Start-Process -FilePath CCleaner.exe -ArgumentList /AUTO
            Write-Log -text ('CCleaner has run and cleaned the machine.')
            }Catch{
            Write-Log -text ('CCleaner was not found or failed to launch.')
        }
    }else{
        Try{
            Start-Process -FilePath CCleaner.exe -ArgumentList /REGISTRY
            Write-Log ('CCleaner has been opened to perform a registry clean.')
        }Catch{
            Write-Log -text ('CCleaner was not found or failed to launch.')
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

    $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"

    If(!(Test-Path $registryPath))

      {
        New-Item -Path $registryPath -Force > $null

        New-ItemProperty -Path $registryPath -Name Logo -Value "C:\\Windows\\System32\\oemlogo.bmp" -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name Manufacturer -Value "Computers4Learning" -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name SupportPhone -Value "(07) 2101 3414" -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name SupportURL -Value "http://www.computers4learning.net.au" -PropertyType String -Force > $null
        
      } Else {

        New-ItemProperty -Path $registryPath -Name Logo -Value "C:\\Windows\\System32\\oemlogo.bmp" -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name Manufacturer -Value "Computers4Learning" -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name SupportPhone -Value "(07) 3620 9640" -PropertyType String -Force > $null
        New-ItemProperty -Path $registryPath -Name SupportURL -Value "http://www.computers4learning.net.au" -PropertyType String -Force > $null
        }
} #End Set-ManufacturerInfo
Function Start-WindowsUpdates{
$updatecollection = New-Object -ComObject Microsoft.Update.UpdateColl
$updatesearcher = New-Object -ComObject Microsoft.Update.Searcher
$updatesession = New-Object -ComObject Microsoft.Update.Session

#Call searcher and write it's results to a variable.
Write-Output "`t Initialising and Checking for Applicable Updates. Please wait ..." -ForeGroundColor "Yellow"
$result = $updatesearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

#Check that there's something in the update list. If not end. 
If ($result.Updates.Count -EQ 0) {
	Write-Output "`t There are no applicable updates for this computer."
}
Else {
	For ($Counter = 0; $Counter -LT $result.Updates.Count; $Counter++) {
		$DisplayCount = $Counter + 1
    		$Update = $result.Updates.Item($Counter)
		$UpdateTitle = $Update.Title
	}
	$Counter = 0
	$DisplayCount = 0
	Write-Output "`t Initialising Download of Applicable Updates ..." -ForegroundColor "Yellow"
	$Downloader = $updatesession.CreateUpdateDownloader()
	$UpdatesList = $result.Updates
	For ($Counter = 0; $Counter -LT $result.Updates.Count; $Counter++) {
		$updatecollection.Add($UpdatesList.Item($Counter)) | Out-Null
		$ShowThis = $UpdatesList.Item($Counter).Title
		$DisplayCount = $Counter + 1
		$Downloader.Updates = $updatecollection
		$Track = $Downloader.Download()
		If (($Track.HResult -EQ 0) -AND ($Track.ResultCode -EQ 2)) {
		}
		Else {
			Write-Output "`t Download Status: FAILED With Error -- $Error()"
			$Error.Clear()
            $failedQA = $true
            $FailedReason = "Windows updates failed to download"
		}
	}
	$Counter = 0
	$DisplayCount = 0
	Write-Output "`t Starting Installation of Downloaded Updates ..." -ForegroundColor "Yellow"
	$Installer = New-Object -ComObject Microsoft.Update.Installer
	For ($Counter = 0; $Counter -LT $updatecollection.Count; $Counter++) {
		$Track = $Null
		$DisplayCount = $Counter + 1
		$WriteThis = $updatecollection.Item($Counter).Title
		$Installer.Updates = $updatecollection
		Try {
			$Track = $Installer.Install()
		}
		Catch {
			[System.Exception]
			$Error.Clear()
		}	
	}
}

}#End Start-WindowsUpdates
Function Send-Report{
    $username = "qa-report"
    $password = "Passw0rd21"
    $secureStringPwd = $password | ConvertTo-SecureString -AsPlainText -Force 
    $creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureStringPwd
    Try{
        New-PSDrive -Name temp -PSProvider FileSystem -Root \\192.168.1.18\qa-report -Credential $creds
        Copy-Item -Path $reportFilePath -Destination temp:\
        Remove-PSDrive -Name temp
    }Catch{
        Write-Output 'Failed to Contact Server to save QA-Report please contact workshop manager.'
    }
}#End Send-Report
Function Delayed-Restart{
    $options = New-ScheduledJobOption -RunElevated -StartIfOnBattery -ContinueIfGoingOnBattery
    $action =  {Restart-Computer -Force}
    $trigger = New-JobTrigger -Once -At (Get-Date).Date.AddSeconds(20)
    Register-Scheduledjob -Name 'Restart' -ScheduledJobOption $options -ScriptBlock $action -Trigger $trigger
}#End Delayed-Restart
Function Check-Network{
        [bool]$connected = $false
        do{
            if(Test-Connection 8.8.8.8 -Count 1 -Quiet){
                $connected = $true
                }Else{
                Write-Output "There is no network connection please fix."
                Write-Output "Before continuing with QA"
                Read-Host "Press any key to try again:"
                }
            }while($connected -eq $false)
}#End Check-Network
Function Get-OfficeSoftwareProtectionPlatform {	
	[OutputType([string])]
	param ()
	
	$File = Get-ChildItem $env:ProgramFiles"\Microsoft Office" -Filter "OSPP.VBS" -Recurse
	If (($File -eq $null) -or ($File -eq '')) {
		$File = Get-ChildItem ${env:ProgramFiles(x86)}"\Microsoft Office" -Filter "OSPP.VBS" -Recurse
	}
	$File = $File.FullName
	Return $File
}#End Get-OfficeSoftwareProtectionPlatform
Function Get-SoftwareLicenseManager {
	[OutputType([string])]
	param ()
	
	$File = Get-ChildItem $env:windir"\system32" | Where-Object { $_.Name -eq "slmgr.vbs" }
	$File = $File.FullName
	Return $File
}#End Get-SoftwareLicenseManager
Function Invoke-OfficeActivation {
	[OutputType([boolean])]
	param
	(
		[ValidateNotNullOrEmpty()][string]$OSPP
	)
	
	$Errors = $false
	Write-Host "Activate Microsoft Office....." -NoNewline
	$Executable = $env:windir + "\System32\cscript.exe"
	$Switches = [char]34 + $OSPP + [char]34 + [char]32 + "/act"
	If ((Test-Path $Executable) -eq $true) {
		$ErrCode = (Start-Process -FilePath $Executable -ArgumentList $Switches -Wait -WindowStyle Minimized -Passthru).ExitCode
	}
	If (($ErrCode -eq 0) -or ($ErrCode -eq 3010)) {
		Write-Host "Success" -ForegroundColor Yellow
	} else {
		Write-Host "Failed with error code"$ErrCode -ForegroundColor Red
		$Errors = $true
	}
	Return $Errors
}#End Invoke-OfficeActivation
Function Invoke-WindowsActivation {
	param([ValidateNotNullOrEmpty()][string]$SLMGR)
	
	$Errors = $false
	Write-Host "Activate Microsoft Windows....." -NoNewline
	$Executable = $env:windir + "\System32\cscript.exe"
	$Switches = [char]34 + $SLMGR + [char]34 + [char]32 + "-ato"
	If ((Test-Path $Executable) -eq $true) {
		$ErrCode = (Start-Process -FilePath $Executable -ArgumentList $Switches -Wait -WindowStyle Minimized -Passthru).ExitCode
	}
	If (($ErrCode -eq 0) -or ($ErrCode -eq 3010)) {
		Write-Host "Success" -ForegroundColor Yellow
	} else {
		Write-Host "Failed with error code"$ErrCode -ForegroundColor Red
		$Errors = $true
	}
	Return $Errors
}#End-WindowsActivation
Function Set-OfficeProductKey {
    [OutputType([boolean])]
	param([ValidateNotNullOrEmpty()][string]$OSPP)
	
	$Errors = $false
	Write-Host "Set Microsoft Office Product Key....." -NoNewline
	$Executable = $env:windir + "\System32\cscript.exe"
	$Switches = [char]34 + $OSPP + [char]34 + [char]32 + "/inpkey:" + $OfficeProductKey
	If ((Test-Path $Executable) -eq $true) {
		$ErrCode = (Start-Process -FilePath $Executable -ArgumentList $Switches -Wait -WindowStyle Minimized -Passthru).ExitCode
	}
	If (($ErrCode -eq 0) -or ($ErrCode -eq 3010)) {
		Write-Host "Success" -ForegroundColor Yellow
	} else {
		Write-Host "Failed with error code"$ErrCode -ForegroundColor Red
		$Errors = $true
	}
	Return $Errors
}#Set-OfficerProductKey
Function Set-WindowsProductKey {
	[CmdletBinding()][OutputType([boolean])]
	param(
		[ValidateNotNullOrEmpty()][string]$SLMGR
	)
	
	$Errors = $false
	Write-Host "Set Microsoft Windows Product Key....." -NoNewline
	$Executable = $env:windir + "\System32\cscript.exe"
	$Switches = [char]34 + $SLMGR + [char]34 + [char]32 + "/ipk" + [char]32 + $WindowsProductKey
	If ((Test-Path $Executable) -eq $true) {
		$ErrCode = (Start-Process -FilePath $Executable -ArgumentList $Switches -Wait -WindowStyle Minimized -Passthru).ExitCode
	}
	If (($ErrCode -eq 0) -or ($ErrCode -eq 3010)) {
		Write-Host "Success" -ForegroundColor Yellow
	} else {
		Write-Host "Failed with error code"$ErrCode -ForegroundColor Red
		$Errors = $true
	}
	Return $Errors
}#End-Windows-ProductKey

#Mark: Main
Check-Network
Write-Output 'Starting Windows Updates in background.'
$j1 = Start-Job -Name 'Updates' -ScriptBlock {Start-WindowsUpdates -ErrorAction 'ContinueSilently'}
Write-Output -InputObject 'Creating Report Log'
New-LogFile
Start-CCleaner -m 0
Write-Output -InputObject 'Retrieving drives and expanding.'
Expand-Drives
Write-Output -InputObject 'Retrieving Installed Physical Memory'
Get-RAM
Write-Output -InputObject 'Configuring OEM Info'
Set-ManufacturerInfo
Set-ComputerIcon
Write-Output -InputObject 'Contacting Registry and checking for Software'
Get-Software $installedsoftware
Write-Output -InputObject 'Begginning Keyboard Test.'
Test-Keyboard
Write-Output -InputObject 'Setting Volume to maximum and testing'
Try{
    [audio]::Mute = $false
    [audio]::Volume = 0.8
}Catch{
    Write-Log 'No Audio Device could be found'
}
Open-InternetExplorer $videourl
Start-CCleaner -m 1
Write-Output -InputObject 'Waiting for Windows updates to complete before checking device manager.'
Wait-Job -Id $j1.Id
Write-Output -InputObject 'Checking for Missing Device Drivers'
Test-DeviceDrivers

#Activate Windows and Office if no Errors found.
#Failed if updates won't run
#Sound or Keyboard are fails
if($failedQA -ne $true){
[string]$OfficeProductKey
[string]$WindowsProductKey
[switch]$ActivateOffice
[switch]$ActivateWindows

Clear-Host
$ErrorReport = $false
$ActivateOffice = Read-Host "Please enter Office Activation Code:"
$ActivateWindows = Read-Host "Please enter Windows Activation Code:"
#Find OSPP.vbs file
$OSPP = Get-OfficeSoftwareProtectionPlatform

#Assign Microsoft Office Product Key
#Check if a value was passed to $OfficeProductKey
If (($OfficeProductKey -ne $null) -and ($OfficeProductKey -ne '')) {
	#Check if OSPP.vbs was found
	If (($OSPP -ne $null) -and ($OSPP -ne '')) {
		#Assign Microsoft Office Product Key
		$Errors = Set-OfficeProductKey -OSPP $OSPP
		If ($ErrorReport -eq $false) {
			$ErrorReport = $Errors
		}
	} else {
		Write-Host "Office Software Protection Platform not found to set the Microsoft Office Product Key" -ForegroundColor Red
	}
}
#Check if $ActivateOffice was selected
If ($ActivateOffice.IsPresent) {
	#Check if OSPP.vbs was found
	If (($OSPP -ne $null) -and ($OSPP -ne '')) {
		#Activate Microsoft Office
		$Errors = Invoke-OfficeActivation -OSPP $OSPP
		If ($ErrorReport -eq $false) {
			$ErrorReport = $Errors
		}
	} else {
		Write-Host "Office Software Protection Platform not found to activate Microsoft Office" -ForegroundColor Red
	}
}

#Check if a value was passed to $WindowsProductKey
If (($WindowsProductKey -ne $null) -and ($WindowsProductKey -ne '')) {
	#Find SLMGR.VBS
	$SLMGR = Get-SoftwareLicenseManager
	#Check if SLMGR.VBS was found
	If (($SLMGR -ne $null) -and ($SLMGR -ne '')) {
		#Assign Windows Product Key
		$Errors = Set-WindowsProductKey -SLMGR $SLMGR
		If ($ErrorReport -eq $false) {
			$ErrorReport = $Errors
		}
	} else {
		Write-Host "Software licensing management tool not found to set the Microsoft Windows Product Key" -ForegroundColor Red
	}
}
#Check if $ActivateWindows was selected
If ($ActivateWindows.IsPresent) {
	#Find SLMGR.VBS
	$SLMGR = Get-SoftwareLicenseManager
	#Check if SLMGR.VBS was found
	If (($SLMGR -ne $null) -and ($SLMGR -ne '')) {
		#Activate Micosoft Windows
		$Errors = Invoke-WindowsActivation -SLMGR $SLMGR
		If ($ErrorReport -eq $false) {
			$ErrorReport = $Errors
		}
	} else {
		Write-Host "Software licensing management tool not found to activate Microsoft Windows" -ForegroundColor Red
	}
}
#Exit with an error code 1 if an error was encountered
If ($ErrorReport -eq $true) {
	Write-Host "Failed to Activate"-ForegroundColor Red
}
}Else{
Write-Host "Test failed on $FailReason"
#Why Test Failed
}#End Activating Windows

#Mark: Finalise
Write-Output 'Send a copy of QA-Report to the server.'
Send-Report
Read-Host -Prompt 'QA Complete Computer will now Restart.'

#Self Removal, must always be last line.
Remove-Item -Path $MyINvocation.InvocationName -Force
Restart-Computer -Force