<#
 Written by Sven Falk - began first of june 2018
 Description: This script will search for the programs 'Dell Command | Update' and 'Dell Command | Control'. If found it will use them to
 update all available drivers. This will include BIOS and Firmware-Settings, which requires temporary disabled bitlocker and BIOS-Passwords.
 ------------------------------------------------------- Define environment -------------------------------------------------------
 Param has to be the first line!
 Defines the parameters which are given by calling this script:
 e.g.: .\update_dell_drivers.ps1 -debug 1
#>
param (
    [int]$debug = 1,
    [string]$OutputFileLocation = "$env:Temp\update_dell_drivers_$(get-date -f yyyy.MM.dd-H.m).log",
    [string]$BIOSPassword = "secret"
)

# Environmentvariables:
# Path to .exe files. 
$DellCommandUpdateExePath = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
$DellCommandConfigureExePath = "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe"

<#
 ---- Exit Codes ----
 These are the codes for Dell Command | Update
     0 = "Successfully patched this system."
     1 = "Reboot requiered"
     2 = "Fatal error during patch-process - Check $($env:Temp) for log files."
     3 = "Error during patch-process - Check $($env:Temp) for log files."
     4 = "Dell Update Command detected an invalid system and stopped."
     5 = "Reboot and scan required."

 Define some custom exit-codes for this script.
 11000 = "This script ran not on a Dell system - exited without any action"
 11001 = "Dell Command | Update software not found - exited without any action"
 11002 = "Dell Command | Update software found but .exe could not be found in defined Path $DellCommandUpdateExePath"
 11003 = "Dell Command | Configure software not found - exited without any action"
 11004 = "Dell Command | Configure software found but .exe could not be found in defined Path $DellCommandConfigureExePath"
 11005 = "BIOS is password protected but this script got the wrong password. Exiting now without actions."
 11006 = "Bitlocker is activated and could not be paused."
 11007 = "Dell Command Update could not import settings-xml-file"
 11008 = "Dell Command Update could not import reset-xml-file"
 11010 = "Unknown result of Dell Command | Update patching."
 11020 = "Could not re-set the BIOS-password. Please check the client!"
#>

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
# e.g.: endscript 2 "The cake is a lie"
function endscript($exitcode, $msg) {
    # Define var $ecode as script-wide so it can be modified by other functions.
    $script:ecode = $exitcode
    debugmsg $msg
    resetSettings
    if ($DebugMessages -eq "1") {Stop-Transcript}
    debugmsg "Exiting with code $ecode"
    exit $ecode
}

# This function is just for better readability of this script
# Call it to print output to console and logfile
# e.g.: debugmsg "The variable xyz contains: $($CheckBIOSPassword.ExitCode)"
function debugmsg($dmsg) {
    if ($DebugMessages -eq "1") {Write-Host "$(get-date -f yyyy.MM.dd_H:m:s) - $dmsg"}
}

# Reset the settings back to the way they were before this script ran:
function resetSettings {
    if ( $BIOSPasswordSet -eq $true ) {
        debugmsg "BIOS-password was set before. Setting it again."
        $setBIOSPassword=Start-Process $DellCommandConfigureExePath -wait -PassThru -ArgumentList "--setuppwd=$BIOSPassword"
        if ( $setBIOSPassword.ExitCode -eq "0" ) {
            debugmsg "Set BIOS-password successfully back to previous value."
        } else {
            debugmsg "Could not re-set the BIOS-password. Please check the client! Exiting with two errorcodes!"
            $script:ecode = "$script:ecode"+11020
        }
    }
    if ( $DCUpolicyImported -eq $true ) {
        debugmsg "Resetting Dell Update | Command Settings back to default."
        # This is done to remove the password from 'Dell Update | Command' (local admin-users could read the password in the gui)
        $DCUResetImport=Start-Process $DellCommandUpdateExePath -wait -PassThru -ArgumentList "/import /policy .\reset.xml"
        if ($DCUResetImport.ExitCode -eq 0) {
            debugmsg "Dell Command Update reset settings via xml-file successfully."
        } else {
            endscript 11007 "Dell Command Update could not import rest-xml-file."
        }
    }


}

# ------------------------------------------------------- End definition of environment ---------------------------------------------------

# -------------------------------------------------------- Check for Dell-environment -----------------------------------------------------

# Check if this is a Dell system:
if (Get-WmiObject win32_SystemEnclosure -Filter: "Manufacturer LIKE 'Dell Inc.'") { 
    $isDellSystem = $true
    debugmsg "This system is identified as Dell-system."
    } else { 
    $manufacturer = $(Get-WmiObject win32_SystemEnclosure | Select-Object Manufacturer)
    endscript 11000 "This system could not be identified as Dell system - Found manufacturer: $manufacturer" 
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
$bitlockerStatus=$($BLinfo.ProtectionStatus)

# Check if BIOS-Password is set
$CheckBIOSPassword=Start-Process $DellCommandConfigureExePath -wait -PassThru -ArgumentList "--setuppwd= --valsetuppwd $BIOSPassword"

    switch ($CheckBIOSPassword.ExitCode) {
        0 { 
            $BIOSPasswordSet = $true
            debugmsg "Found and removed BIOS-password successfully."
        }
        157 { 
            endscript 11005 "BIOS is password protected but this script got the wrong password. Exiting now without actions."
        }
        240 { 
            $BIOSPasswordSet = $false
            debugmsg "No BIOS-password was set - skipped removing BIOS-password."
        }
    }

# --------------------------------------------------------------- Tasks -------------------------------------------------------------------
# Pause bitlocker if enabled
if( $bitlockerStatus -eq "On") {
    debugmsg "Bitlocker is activated - pausing it until next reboot."
    $BLpause=Start-Process $env:SystemDrive\Windows\System32\manage-bde.exe -wait -PassThru -ArgumentList "-protectors -disable $env:SystemDrive"
    $bitlockerPause = $($BLpause.ExitCode)
        if( $bitlockerPause -eq 0) {
            debugmsg "Bitlocker paused successfully for drive $($env:SystemDrive)"
            } else {
            endscript 11006 "Bitlocker is activated and could not be paused."
            }
}

# Import Settings for Dell Update Command
$DCUImport=Start-Process $DellCommandUpdateExePath -wait -PassThru -ArgumentList "/import /policy .\lhind_ol_settings.xml"
if ($DCUImport.ExitCode -eq 0) {
    debugmsg "Dell Command Update imported settings via xml-file successfully."
    $DCUpolicyImported = $true
} else {
    endscript 11007 "Dell Command Update could not import settings-xml-file."
}

# Start patching
debugmsg "Starting Patchprocess silently. Logging into $env:Temp\Dell_Command_Update_Patchlogs_$(get-date -f yyyy.MM.dd_H-m)"
$DCUPatching=Start-Process $DellCommandUpdateExePath -WindowStyle hidden -wait -PassThru -ArgumentList "/silent /log $env:Temp\Dell_Command_Update_Patchlogs_$(get-date -f yyyy.MM.dd_H-m)"

# Interpret the returncode of patching-process:
switch ( $DCUPatching.ExitCode ) {
    0 {
        endscript 0 "Successfully patched this system."
    }
    1 { 
        endscript 1 "Successfully patched this system. Reboot requiered."
    }
    2 {
        endscript 2 "Fatal error during patch-process - Check $($env:Temp) for log files."
    }
    3 {
        endscript 3 "Error during patch-process - Check $($env:Temp) for log files."
    }
    4 {
        endscript 4 "Dell Update Command detected an invalid system and stopped."
    }
    5 {
        endscript 5 "Successfully patched this system. Reboot and scan required."
    }
}

endscript 11010 "Unknown result of Dell Command | Update patching."