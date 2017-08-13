<#
    Beta C4L QA Script

    The purpose of this script is to automate the process of quality checking 
    refurbished machines on the computers 4 learning project.

    Written By Mitchell Beare and Chad Gay
    2017
#>

#Function Declarations
Function Get-Software {
    Param([string]$app)

    Write-Output "Checking 64bit registry for $app."
    $64bit = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Select-Object DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | 
    Out-String
    if ($64bit -eq ''){
      Write-Output "Checking 32bit registry for $app."
      $32bit = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
      Select-Object DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | 
      Out-String
      Write-Log $32bit
    }elseif($32bit -eq '') {
        Write-Log "$app Could not be found"
    }else{
        Write-Log $64bit
    }
}
Function Test-DeviceDrivers{

    #For formatting:
    $result = @{Expression = {$_.Name}; Label = 'Device Name'},
              @{Expression = {$_.DeviceID}; Label = 'Device ID'},
              @{Expression = {$_.ConfigManagerErrorCode} ; Label = 'Status Code' }

    #Checks for devices whose ConfigManagerErrorCode value is greater than 0, i.e has a problem device.
    $missingdrivers = Get-ciminstance -Class Win32_PnpEntity -Namespace Root\CIMV2 | 
    Where-Object {$_.ConfigManagerErrorCode -gt 0 } | Out-String

    if($missingdrivers -eq $null){
      Write-Log('No Device Drivers are Missing on this machine.')
    }else{
      ForEach($missingdrive in $missingdrivers){
      Write-Log("The drivers were not found for `n $missingdrive")
      }
    }
}#End Test-Drivers
Function Set-AudioVolume{
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
}#End Set-Volume
Function Expand-Drives{
        $maxsize = (Get-PartitionSupportedSize -DriveLetter C).sizemax
        $drivesize = (Get-Partition -DriveLetter C).size
         if($drivesize -eq $maxsize){
            Write-Output 'C:\ Drive is already at maximum size'
        }Else{
            Write-Output 'C:\ Drive does not currently fill the Harddrive Expanding...'
            Resize-Partition -DriveLetter C -Size $maxsize
            Write-Output "Successfully expanded 'C:\' Drive."
        }
        $maxsize = $maxsize/1024/1024/1024
        $maxsize = [Math]::Round($maxsize)
        Write-Log "C:\ is $($maxsize)GB"
}#End Expand-Drives
Function Start-Video{

  ## URL for video playback test
  $url = 'https://www.youtube.com/watch?v=wZZ7oFKsKzY'

  $IE=new-object -com internetexplorer.application
  $IE.navigate2($url)
  $IE.visible=$true
  $input = Read-Host 'Was Audio heard Y/N'
  $check = $false
  Do{
    if($input -eq 'Y' -or $input -eq 'y'){
      Write-Log 'Audio is functioning correctly.'
      $check = $true
    }Elseif($input -eq 'N' -or $input -eq 'n'){
      Write-Log 'Audio failed to be heard please check speakers and audio drivers.'
      $check = $true
    }Else{
      Write-Log 'Invalid input detected'
    }
  }While($check -eq $false)
  
}#End Start-Video
Function Create-Log{
  ## File path for QA_Report
  $script:reportFilePath = "$env:Public\Desktop\QA_Report.txt"

  $today = Get-Date

  ## Delete file if it already exists
  If (Test-Path $reportFilePath) {
    Remove-Item $reportFilePath
  }

  Add-Content $reportFilePath "QA Report For Computer: $env:computername`r`n"
  Add-Content $reportFilePath "Report Created On: $today`r"
  Add-Content $reportFilePath "==============================================================================`r`n"
}#End Create-Log
Function Write-Log {
  Param([string]$text)
  Add-Content $reportFilePath "`n$($text)"
  
}#End Write-Log
Function Get-RAM{
    $ram = Get-Ciminstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum |Select-Object -ExpandProperty Sum 
    $ram = $ram/1024/1024/1024
    $ram = [Math]::Round($ram)
    Write-Log "There is $($ram)GB of RAM installed on this machine `n"
}#End Get-Ram
Function Test-Keyboard{
  $teststring ='The quick brown fox jumps over the lazy dog. 1234567890'
  $exit = $false
  Do{
    Write-Output 'Please type the following exactly as it appears:'
    $testinput = Read-Host "$teststring"
    if ($teststring -eq $testinput){
      Write-Output 'Keyboard test was successful continuing'
      Write-Log 'Keyboard test was successful'
      $exit = $true
    }else{
      Write-Output "Keyboard test failed you typed: `n$testinput"
      $continue = Read-Host "Would you like to try again? Y/N"
      if($continue -eq 'n' -or $continue -eq 'N'){
        Write-Log 'Keyboard test failed'
        $exit = $true
      }
    }
    Clear-Host
  }While($exit -eq $false)
}#End Test-Keyboard
Function Start-CCleaner {
  Write-Output 'Starting CCleaner quietly and running'
  Try{
    Start-Process CCleaner.exe /AUTO
    Write-Log('CCleaner has run and cleaned the machine.')
  }Catch{
    Write-Log ('CCleaner was not found or failed to launch.')

  }
}#End Start-CCleaner


#Main Code
Write-Output 'Creating Report Log'
Create-Log
Write-Output 'Retrieving drives and expanding.'
Expand-Drives
Write-Output 'Retrieving Installed Physical Memory'
Get-RAM
Write-Output 'Contacting Registry and checking for Software'
Get-Software 'Adobe Acrobat Reader'
Get-Software 'Firefox'
Get-Software 'VLC'
Get-Software 'Panda'
Write-Output 'Begginning Keyboard Test.'
Test-Keyboard
Write-Output 'Setting Volume to maximum and testing'
Set-AudioVolume '0.8'
Start-Video($url)
Start-CCleaner
Write-Output 'Waiting for 5 minutes for drivers to install'
Start-Sleep -s 300
Write-Output 'Checking for Missing Device Drivers'
Test-DeviceDrivers
Read-Host 'QA Complete Computer will now Restart.'
Restart-Computer -Force
#End Main