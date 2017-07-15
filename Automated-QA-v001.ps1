<#
Beta C4L QA Script

The purpose of this script is to automate the process of quality checking 
refurbished machines on the computers 4 learning project.

Written By Mitchell Beare and Chad Gay
2017
#>

#Global Variable Declarations

#Function Declarations
Function Get-Software($app) {

    $64bit = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | Format-Table –AutoSize

     if ($64bit -eq $null){
        $32bit = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Where-Object -FilterScript {$_.DisplayName -like "*$app*"} | Format-Table –AutoSize
        $32bit
     } else {
        $64bit
     }

}#End Get-Software
Function Test-DeviceDrivers{

    #For formatting:
    $result = @{Expression = {$_.Name}; Label = "Device Name"},
              @{Expression = {$_.ConfigManagerErrorCode} ; Label = "Status Code" }

    #Checks for devices whose ConfigManagerErrorCode value is greater than 0, i.e has a problem device.
    Get-WmiObject -Class Win32_PnpEntity -ComputerName localhost -Namespace Root\CIMV2 | Where-Object {$_.ConfigManagerErrorCode -gt 0 } | Format-Table $result -AutoSize

}#End Test-Drivers
Function Set-Volume{

}#End Set-Volume
Function Test-Speakers{
}#End Test-Speakers
Function Expand-Drives{
    $drives = Get-PSDrive -PSProvider FileSystem | Select-Object Name
    foreach($drive in $drives){
        $maxsize = (Get-PartitionSupportedSize -DriveLetter $drive).sixemax
        $driveSize = (Get-PartitionSupportedSize -DriveLetter $drive).size
         if($driveSize = $maxSize){
            Write-Verbose "$drive Drive is already at maximum size"
        }Else{
            Resize-Partition -DriveLetter $drive -Size $MaxSize
            Write-Verbose "Successfully expanded $drive Drive."
        }
        $MaxSize = $MaxSize/1024/1024/1024
        $MaxSize = [Math]::Round($MaxSize)
        $MaxSize = "HDD Size $mazsize(GB): " + $MaxSize
    }
}#End Expand-Drives
Function Start-Video{
}#End Start-Video
Function Invoke-CCleaner{
}#End Invoke-CCleanerx
#Main Code

Write-Verbose 'Retrieving drives and expanding.'
Expand-Drives

Write-Verbose 'Contacting Registry and checking for Software'
Get-Software 'Adobe Reader'
Get-Software 'Firefox'
Get-Software 'VLC Player'
Get-Software 'Panda'

Write-Verbose 'Setting Volume to maximum and testing'
if(Set-Volume '100' -eq $true){
    Test-Speakers
}else{
    #Give an error to report
}
<#
start-process $msbuild $arguments 

#>
