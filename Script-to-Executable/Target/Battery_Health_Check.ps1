#MOE Powershell script template
#Written by mbear0
#Header
[CmdletBinding()]
    Param([Parameter(Mandatory=$false)][String]$action)
if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{Write-Output 'Running as Administrator!'}
else
{Write-Output 'Running Limited!'}
#End of Header


#Body
#Write your script from here down


function Find-Folders{
Add-Type -AssemblyName System.Windows.Forms
$FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog -Property @{
    SelectedPath = 'C:\’
}
 
[void]$FolderBrowser.ShowDialog()
$FolderBrowser.SelectedPath
}

Function Test-BatteryHealth 
{ 
    $fullchargecapacity = (Get-WmiObject -Class "BatteryFullChargedCapacity" -Namespace "ROOT\WMI").FullChargedCapacity 
    $designcapacity = (Get-WmiObject -Class "BatteryStaticData" -Namespace "ROOT\WMI").DesignedCapacity 
    $batteryhealth = ($fullchargecapacity / $designcapacity) * 100 
    if ($batteryhealth -gt 100) {$batteryhealth = 100} 
    return [decimal]::round($batteryhealth)  
} 

Function Report-BatteryHealth
{ 
$BatteryID = (Get-WmiObject -Class "BatteryStaticData" -Namespace "ROOT\WMI").SerialNumber
$BatteryManufacturer = (Get-WmiObject -Class "BatteryStaticData" -Namespace "Root\WMI").ManufactureName
$reportpath = Find-Folders
$reportfile = $reportpath + "\Battery Health Report.log"
     
    Add-Content $reportfile "`n Machine $envComputerName Assessed on $date" 
    Add-Content $reportfile "`n Battery ID is: $BatteryID and was manufactured by $Batterymanufacturer"
    Add-Content $reportfile "`n On the last full charge the battery could hold -- $batteryhealth% -- of its original capacity" 
    Add-Content $reportfile "`n" 
} 

Function Show-BatteryHealth 
{ 
    if ($batteryhealth -gt 90) { Write-Host "Last full charge was $batteryhealth% of original capacity`n" -ForegroundColor black -BackgroundColor Green } 
    if ($batteryhealth -lt 89 -and $batteryhealth -gt 70) { Write-Host "Last full charge was $batteryhealth% of original capacity`n" -ForegroundColor black -BackgroundColor Yellow } 
    if ($batteryhealth -lt 69) { Write-Host "Last full charge was $batteryhealth% of original capacity`n" -ForegroundColor black -BackgroundColor Red } 
} 

$date = Get-Date -format "dd-MMM-yyyy HH:mm"
$batteryhealth = Test-BatteryHealth

$title = "Select Action:"
$message = "Would you like to show health or report it?"

$Show = New-Object System.Management.Automation.Host.ChoiceDescription "&Show", `
         "Shows the report to powershell then exits."

$Report = New-Object System.Management.Automation.Host.ChoiceDescription "&Report", `
    "Writes the result to a log file in a location of your choice."

$Both = New-Object System.Management.Automation.Host.ChoiceDescription "&Both",
    "Shows health on the console and writes to a log"

$options = [System.Management.Automation.Host.ChoiceDescription[]]($Show, $Report, $Both)

$action = $host.ui.PromptForChoice($title, $message, $options, 0)
 
switch ($action) { 
    0 {Show-BatteryHealth} 
    1 {Report-BatteryHealth} 
    2 {Show-BatteryHealth
    Report-BatteryHealth}
     
    default { 
        $wshell = New-Object -ComObject Wscript.Shell 
        $continue = $wshell.Popup("You haven't specified a parameter such as show or report. `n`nPress OK to continue and log battery capacity information to a report file",0,"No Parameter",0x1)  
            if($continue -ne 1) {Exit 1} 
        Show-BatteryHealth 
        Report-BatteryHealth 
    } 
} 
Pause
Exit 0