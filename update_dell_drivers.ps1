# Written by Sven Falk - began first of june 2018
# Description: This script will search for the program 'Dell Command | Update' and if found, will use it to
# update all available drivers. This will include BIOS and Firmware-Settings, which requires temporary disabled bitlocker and BIOS-Passwords.
# ------------------------------------------------------- Define environment -------------------------------------------------------
# Param has to be the first line!
# Defines the parameters which are given by calling this script:
# e.g.: .\update_dell_drivers.ps1 -debug 1
param (
    [int]$debug = 1,
    [string]$OutputFileLocation = "$env:Temp\update_dell_drivers_$(get-date -f yyyy.MM.dd-H.m).log",
    [string]$BIOSPassword = "secret"
)


# Environmentvariables:
# Path to dcu-cli.exe file. 
$DellCommandUpdateExePath = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
$DellCommandConfigureExePath = "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe"


# ---- Exit Codes ----
# Setup-routines will exit with their own exit-codes.
# Define some custom exit-codes for this script.
#11000 = "This script ran not on a Dell system - exited without any action"
#11001 = "Dell Command | Update software not found - exited without any action"
#11002 = "Dell Command | Update software found but .exe could not be found in defined Path $DellCommandUpdateExePath"
#11003 = "Dell Command | Configure software not found - exited without any action"
#11004 = "Dell Command | Configure software found but .exe could not be found in defined Path $DellCommandConfigureExePath"
#11005 = ""
#11006 = ""
#11010 = ""


# ----------------------------------------------------------------- Debugging -------------------------------------------------------------
# Enable debugging (1) or disable (0)
# Powershelldebugging:
Set-PSDebug -Trace 0
# Enable Debug-Write-Host-Messages:
$DebugMessages = $debug
#
# Send all Write-Host messages to console and to the file defined in $OutputFileLocation
if ($DebugMessages -eq "1") {
    # Stop transcript - just in case it's running in another PS-Script:
    $ErrorActionPreference="SilentlyContinue"
    Stop-Transcript | out-null
    # Start transcript of all output into a file:
    $ErrorActionPreference = "Continue"
    Start-Transcript -path $OutputFileLocation -append
}


# --------------------------------------------------------------- Functions --------------------------------------------------------------

# End this script with message and errorlevel
# call this function with "endscript errormessage errorlevel" 
# e.g.: "endscript 2 "The cake is a lie""
function endscript($exitcode, $msg) {
    # Debug info:
    if ($DebugMessages -eq "1") {Write-Host $msg }
    if ($DebugMessages -eq "1") {Stop-Transcript}
    exit $exitcode
}

# ------------------------------------------------------- End definition of environment ---------------------------------------------------

# -------------------------------------------------------- Check for Dell-environment -----------------------------------------------------

# Check if this is a Dell system:
if (Get-WmiObject win32_SystemEnclosure -Filter: "Manufacturer LIKE 'Dell Inc.'") { 
    $isDellSystem = $true 
    } else { 
    $manufacturer = $(Get-WmiObject win32_SystemEnclosure | Select-Object Manufacturer)
    endscript 11000 "This system could not be indentified as Dell system - Found manufacturer: $manufacturer" 
}

# Check if 'Dell Command | Update' is installed:
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Dell Command | Update*"} | ForEach-Object -process { $isDellCommandUpdateInstalled = $true }
if ($isDellCommandUpdateInstalled -eq $false) {
    endscript 11001 "Dell Command | Update software not found - exited without any action"
}

# Check if the Dell Command | Update command-line exe-file exists:
if (Test-Path $DellCommandUpdateExePath) {
    $foundDellCommandUpdateExe = $true
} else {
    endscript 11002 "Dell Command | Update software found but .exe could not be found in defined Path $DellCommandUpdateExePath"
}

# Check if 'Dell Command | Configure' is installed:
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Dell Command | Configure*"} | ForEach-Object -process { $isDellCommandConfigureInstalled = $true }
if ($isDellCommandConfigureInstalled -eq $false) {
    endscript 11003 "Dell Command | Configure software not found - exited without any action"
}

# Check if the Dell Command | Configure command-line exe-file exists:
if (Test-Path $DellCommandConfigureExePath) {
    $foundDellCommandConfigureExe = $true
} else {
    endscript 11004 "Dell Command | Configure software found but .exe could not be found in defined Path $DellCommandConfigureExePath"
}

# -------------------------------------------------------- Check security-settings --------------------------------------------------------

# Check if Bitlocker is enabled on Systemdrive:
$BLinfo = Get-Bitlockervolume -MountPoint $env:SystemDrive 
$bitlockerStatus=$($blinfo.ProtectionStatus)

# Check if BIOS-Password is set
$CheckBIOSPassword= Start-Process $DellCommandConfigureExePath -wait -PassThru -ArgumentList "--setuppwd=","--valsetuppwd $BIOSPassword"

Write-Output $CheckBIOSPassword