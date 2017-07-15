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
<#
Sounds like Chad's Job

#>

}#End Get-Software
Function Test-DeviceDrivers{

}#End Test-Drivers
Function Set-Volume{

}#End Set-Volume
Function Test-Speakers{
}#End Test-Speakers
Function Expand-Drives{
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
