# Written by Sven Falk - began first of june 2018
# Description: This script will search for the program 'Dell Command | Update' and if found, will use it to
# update all available drivers. This will include BIOS and Firmware-Settings, which requires temporary disabled bitlocker and BIOS-Passwords.
# ------------------------------------------------------- Define environment -------------------------------------------------------
# Param has to be the first line!
# Defines the parameters which are given by calling this script:
# e.g.: .\check_previous_Versions.ps1 -software "7-Zip" -version "16.01" -uninstall "yes" -debug 1
param (
    [int]$debug = 0,
    [string]$OutputFileLocation = "$env:Temp\update_dell_drivers_$(get-date -f yyyy.MM.dd-H.m).log"
)
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

# Check if 'Dell Command | Update' is installed
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*Dell Command | Update*"} | ForEach-Object -process { $isDellCommandUpdateInstalled = $true }






# -------------------------- Tasks --------------------------


$BLinfo = Get-Bitlockervolume -MountPoint $env:SystemDrive && $bitlockerStatus=$($blinfo.ProtectionStatus)


Write-Output $bitlockerStatus
