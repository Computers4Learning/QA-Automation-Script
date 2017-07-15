<#
    Beta C4L QA Script

    The purpose of this script is to automate the process of quality checking 
    refurbished machines on the computers 4 learning project.

    Written By Mitchell Beare and Chad Gay
    2017
#>

#Global Variable Declarations

#Function Declarations
Function Get-Software{
    param([string]$app)
    Write-Verbose "Checking 64bit registry for $app."
    $64bit = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | Format-Table -AutoSize
    if ($64bit -eq $null){
      Write-Verbose "Checking 32bit registry for $app."
        $32bit = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | Format-Table -AutoSize
        $32bit
    }elseif($32bit -eq $null) {
        Write-Error "$app Could not be found."
    }else{
        $64bit
    }
}
Function Test-DeviceDrivers{

    #For formatting:
    $result = @{Expression = {$_.Name}; Label = 'Device Name'},
              @{Expression = {$_.ConfigManagerErrorCode} ; Label = 'Status Code' }

    #Checks for devices whose ConfigManagerErrorCode value is greater than 0, i.e has a problem device.
    Get-WmiObject -Class Win32_PnpEntity -ComputerName localhost -Namespace Root\CIMV2 | Where-Object {$_.ConfigManagerErrorCode -gt 0 } | Format-Table $result -AutoSize

}#End Test-Drivers
Function Set-AudioVolume{
    Param([double]$volume)
    
  Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
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
interface IMMDevice {
  int Activate(ref System.Guid id, int clsCtx, int activationParams, out IAudioEndpointVolume aev);
}
[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
  int f(); // Unused
  int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);
}
[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }

public class Audio {
  static IAudioEndpointVolume Vol() {
    var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;
    IMMDevice dev = null;
    Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(/*eRender*/ 0, /*eMultimedia*/ 1, out dev));
    IAudioEndpointVolume epv = null;
    var epvid = typeof(IAudioEndpointVolume).GUID;
    Marshal.ThrowExceptionForHR(dev.Activate(ref epvid, /*CLSCTX_ALL*/ 23, 0, out epv));
    return epv;
  }
  public static float Volume {
    get {float v = -1; Marshal.ThrowExceptionForHR(Vol().GetMasterVolumeLevelScalar(out v)); return v;}
    set {Marshal.ThrowExceptionForHR(Vol().SetMasterVolumeLevelScalar(value, System.Guid.Empty));}
  }
  public static bool Mute {
    get { bool mute; Marshal.ThrowExceptionForHR(Vol().GetMute(out mute)); return mute; }
    set { Marshal.ThrowExceptionForHR(Vol().SetMute(value, System.Guid.Empty)); }
  }
}
'@
  [Audio]::Volume  = $volume # 0.2 = 20%, etc.
  [Audio]::Mute = $false  # Set to $false to un-mute
}#End Set-Volume
Function Test-Speakers{
  Read-Host 'Audio is about to be tested press anything to continue:'
  [console]::beep(440,500)       
  [console]::beep(440,500) 
  [console]::beep(440,500)        
  [console]::beep(349,350)        
  [console]::beep(523,150)        
  [console]::beep(440,500)        
  [console]::beep(349,350)        
  [console]::beep(523,150)        
  [console]::beep(440,1000) 
  [console]::beep(659,500)        
  [console]::beep(659,500)        
  [console]::beep(659,500)        
  [console]::beep(698,350)        
  [console]::beep(523,150)        
  [console]::beep(415,500)        
  [console]::beep(349,350)        
  [console]::beep(523,150)        
  [console]::beep(440,1000)
  $validresponse = $false
  Do{
    $audioresponse = Read-Host 'Were beeps heard Y/N'
    if($audioresponse -eq 'y' -or $audioresponse -eq 'Y'){
      $validresponse = $true
      Write-Verbose 'Audio Test Successful'
    }elseif($audioresponse -eq 'n' -or $audioresponse -eq 'N'){
      $validresponse = $true
      Write-Verbose 'Audio Test Failed'
      #Feature write failure to report
    }else{
      $audioresponse = Write-Host 'Invalid Input please enter Y for yes N for no'
    }
  }While($validresponse -eq $false)
}#End Test-Speakers
Function Expand-Drives{
    $drives = Get-PSDrive -PSProvider FileSystem | Select-Object Name
    foreach($drive in $drives){
        $maxsize = (Get-PartitionSupportedSize -DriveLetter $drive).sixemax
        $driveSize = (Get-PartitionSupportedSize -DriveLetter $drive).size
         if($driveSize = $maxSize){
            Write-Verbose "$drive Drive is already at maximum size"
        }Else{
            Resize-Partition -DriveLetter $drive -Size $maxSize
            Write-Verbose "Successfully expanded $drive Drive."
        }
        $maxSize = $maxSize/1024/1024/1024
        $maxSize = [Math]::Round($maxSize)
        $maxSize = "HDD Size $mazsize(GB): " + $MaxSize
    }
}#End Expand-Drives
Function Start-Video{
}#End Start-Video
Function Invoke-CCleaner{
  Write-Verbose 'Running CCleaner'
  Start-Process CClearner.exe -ArgumentList /AUTO
  #Feature write to report
}#End Invoke-CCleaner
#Main Code

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

Invoke-CCleaner
<#
    start-process $msbuild $arguments 

#>
