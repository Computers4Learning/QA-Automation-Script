#View Usage.txt to see how line 4 can be modified to change compile steps
#Credit goes to Markus Scholtes for creating ps2exe.ps1 this is just an execution script
$scriptpath = Split-Path $SCRIPT:MyInvocation.MyCommand.Path -parent
ls "$scriptpath\Target\*.ps1" | %{
	."$scriptpath\ps2exe.ps1" "$($_.Fullname)" "$($_.Fullname -replace '.ps1','.exe')" -verbose -requireadmin -iconfile 'qa.ico'
}
$null = Read-Host "Press enter to exit"