# Written by Sven Falk - began first of june 2018
# Description: This script will search for the program 'Dell Command | Update' and if found, will use it to
# update all available drivers. This will include BIOS and Firmware-Settings, which requires temporary disabled bitlocker and BIOS-Passwords.
# ------------------------------------------------------- Define environment -------------------------------------------------------
# Param has to be the first line!
# Defines the parameters which are given by calling this script:
# e.g.: .\check_previous_Versions.ps1 -software "7-Zip" -version "16.01" -uninstall "yes" -debug 1
param (
    [int]$debug = 1,
    [string]$OutputFileLocation = "$env:Temp\update_dell_drivers_$(get-date -f yyyy.MM.dd-H.m).log"
)

# ---- Exit Codes ----
# Setup-routines will exit with their own exit-codes.
# Define some custom exit-codes for this script.
#   11000 | Dell Command | Update software not found - exited without any action
#   11001 | Undefined error
#   11002 | 
#   11003 | 
#	11004 | 
#	11005 | 
#	11006 | 
#   11010 | 




# ---- Debugging ----
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

# ------------------------------------------------------- End definition of environment ---------------------------------------------------

# -------------------------------------------------------- Lets take a look around --------------------------------------------------------

# Check if this is a Dell system:
if (Get-WmiObject win32_SystemEnclosure -Filter: "Manufacturer LIKE 'Dell Inc.'") { $isDellSystem = $true } else { $isDellSystem = $False }

# Check if 'Dell Command | Update' is installed:
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Dell Command | Update*"} | ForEach-Object -process { $isDellCommandUpdateInstalled = $true }

# Check if Bitlocker is enabled on Systemdrive:
$BLinfo = Get-Bitlockervolume -MountPoint $env:SystemDrive 
$bitlockerStatus=$($blinfo.ProtectionStatus)


# --------------------------------------------------------------- Functions --------------------------------------------------------------

# End this script with message and errorlevel
# call this function with "endscript errormessage errorlevel" 
# e.g.: "endscript "The cake is a lie" 2"
function endscript($msg, $exitcode) {
    # Debug info:
    if ($DebugMessages -eq "1") {Write-Host "$msg"}
    if ($DebugMessages -eq "1") {Stop-Transcript}
    exit $exitcode
}


# -------------------------- Tasks --------------------------
if ($isDellSystem -eq $true) { endscript "The cake is a lie" 2 }