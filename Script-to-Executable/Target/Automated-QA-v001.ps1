<#
    Beta C4L QA Script

    The purpose of this script is to automate the process of quality checking 
    refurbished machines on the computers 4 learning project.

    Written By Mitchell Beare and Chad Gay
    2017
#>

#Global Variable Declarations

 
#Function Declarations
Function Get-Software {
    Param([string]$app)

    Write-Verbose "Checking 64bit registry for $app."
    $64bit = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Select-Object DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | 
    Out-String

    if ($64bit -eq $null){
      Write-Verbose "Checking 32bit registry for $app."
        $32bit = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | 
        Out-String
        ## Execute query
        $32bit
        Write-Log($32bit)

    }elseif($32bit -eq $null) {
        $missing = "$app Could not be found."
        Write-Log($missing)
    }else{
        ## Execute query
        $64bit
        Write-Log($64bit)
    }
}
Function Test-DeviceDrivers{

    #For formatting:
    $result = @{Expression = {$_.Name}; Label = 'Device Name'},
              @{Expression = {$_.DeviceID}; Label = 'Device ID'},
              @{Expression = {$_.ConfigManagerErrorCode} ; Label = 'Status Code' }

    #Checks for devices whose ConfigManagerErrorCode value is greater than 0, i.e has a problem device.
    $missingdrivers = Get-WmiObject -Class Win32_PnpEntity -ComputerName localhost -Namespace Root\CIMV2 | 
    Where-Object {$_.ConfigManagerErrorCode -gt 0 } | Out-String

    if($missingdrivers -eq $null){
      Write-Log('No Device Drivers are Missing on this machine.')
    }else{
      ForEach($missingdrive in $missingdrivers){
      Write-Log("The drivers were not found for `n $missingdrive")
    }
    }
    #$test= Get-WmiObject -Class Win32_PnpEntity -ComputerName localhost -Namespace Root\CIMV2 | Format-Table $result -AutoSize
}#End Test-Drivers
Function Set-Volume{
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
    $drives = Get-PSDrive -PSProvider FileSystem | Select-Object Name
    foreach($drive in $drives){
        $maxsize = (Get-PartitionSupportedSize -DriveLetter $drive.name).sixemax
        $driveSize = (Get-PartitionSupportedSize -DriveLetter $drive.name).size
         if($driveSize = $maxSize){
            Write-Verbose "$drive Drive is already at maximum size"
        }Else{
            Resize-Partition -DriveLetter $drive -Size $maxSize
            Write-Verbose "Successfully expanded $drive Drive."
        }
        $maxSize = $maxSize/1024/1024/1024
        $maxSize = [Math]::Round($maxSize)
        $maxSize = "HDD Size $mazsize(GB): " + $MaxSize
        Write-Log($maxsize)
    }
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
    if($input = Y -or $input = y){
      Write-Log 'Audio is functioning correctly.'
      $check = $true
    }Elseif($input = N or $input = n){
      Write-Log 'Audio failed to be heard please check speakers and audio drivers.'
      $check = $true
    }Else{
      Write-Log 'Invalid input detected'
    }
  }While($check = false)
  
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

  ##Param([string]$text) 
  Add-Content $reportFilePath "`n$($text)"
  
}#End Write-Log

#Main Code
Write-Verbose 'Creating Report Log'
Create-Log

Write-Verbose 'Retrieving drives and expanding.'
Expand-Drives

Write-Verbose 'Contacting Registry and checking for Software'
Get-Software 'Adobe Reader'
Get-Software 'Firefox'
Get-Software 'VLC Player'
Get-Software 'Panda'

Write-Verbose 'Setting Volume to maximum and testing'
Set-AudioVolume '0.8'
Test-Speakers
Start-Video($url)

Write-Verbose 'Starting CCleaner quietly and r'
Try{
    Start-Process CCleaner.exe /AUTO
    Write-Log('CCleaner has run and cleaned the machine.')
}Catch{
    Write-Log ('CCleaner was mot found or failed to launch.')

}
Read-Host 'QA Complete Computer will now Restart.'
Restart-Computer -Force