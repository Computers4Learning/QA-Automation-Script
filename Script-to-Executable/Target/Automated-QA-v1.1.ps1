<# Mark: About Script
    C4L Quality Assurance Script

    The purpose of this script is to automate the process of quality checking 
    refurbished machines on the computers 4 learning project.

    Written By Mitchell Beare and Chad Gay
    2017
#>

#Mark: Iniatialise
$ErrorActionPreference = 'Inquire'
$DebugPreference = 'SilentlyContinue'

#Mark: Configuration Variables
[string]$videourl = 'https://www.youtube.com/watch?v=wZZ7oFKsKzY'
[string[]]$installedsoftware = ('Panda','VLC','Firefox','Adobe Acrobat Reader')

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

  $today = Get-Date

  ## Delete file if it already exists
  If (Test-Path -Path $reportFilePath) {
    Remove-Item -Path $reportFilePath
  }

  Add-Content -Path $reportFilePath -Value "QA Report For Computer: $env:computername`r`n"
  Add-Content -Path $reportFilePath -Value "Report Created On: $today`r"
  Add-Content -Path $reportFilePath -Value "==============================================================================`r`n"
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

#Mark: Main
#Start-WindowsUpdates -ErrorAction 'ContinueSilently'
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
Write-Output -InputObject 'Waiting for 5 minutes for drivers to install, then checking device manager for errors.'
Start-Sleep -Seconds 300
Write-Output -InputObject 'Checking for Missing Device Drivers'
Test-DeviceDrivers
Read-Host -Prompt 'QA Complete Computer will now Restart.'

#Mark: Finalise
Write-Output 'Send a copy of QA-Report to the server.'
Send-Report
Restart-Computer -Wait -For PowerShell -Force
#Self Removal, must always be last line.
Remove-Item -Path $MyINvocation.InvocationName