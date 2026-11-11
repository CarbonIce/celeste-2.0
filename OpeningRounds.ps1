<#

1600 - OPENING ROUNDS

Initial tasks to complete on the startup of the competition (tailored to BoilerStorm).
To be run on CAI-DC01
Enumerates Domain
Starts up Dispel Magic (User Auditing)
Starts up Stalker (IOC detection)
Starts up important diagnostic processes
Starts up PersistanceSniper
Checks if Windows Firewall is functional; if it is, set specific rules, if not, notify
#>

#Requires -RunAsAdministrator
Import-Module ActiveDirectory

function Write-Output {
    param {
        $text,
        $code = "none"
    }
    if ($code -eq "info") {
        $color = "Cyan"
        $symbol = "*"
    } elseif ($code -eq "warn") {
        $color = "Yellow"
        $symbol = "!"
    } elseif ($code -eq "error") {
        $color = "Red"
        $symbol = "X"
    } elseif ($code -eq "success") {
        $color = "Green"
        $symbol = "+"
    } else {
        $color = "White"
        $symbol = "*"
    }

    Write-Host "[$symbol] $text" -ForegroundColor $color
}

$dcName="CAI-DC01"
$dcDNS="closedai.com"
$dcIP="10.42.0.10"

# Ensure EternalBlue and ZeroLogon are guarenteed to be patched with no way to reopen those holes

# Start up Dispel Magic (User Auditing)
Start-Process -FilePath "./DispelMagic.ps1"
# Install Sysmon
Write-Output "Installing Sysmon..."
Start-Process -FilePath "./Tools/Sysmon64.exe /accepteula -i ./Tools/sysmonconfig-export.xml"
# Start up important diagnostic processes
Write-Output "Starting Autoruns, Process Explorer, TCP view, so on and so on and auxiliary scripts..."
Start-Process -FilePath "./Tools/Autoruns64.exe /accepteula"
Start-Process -FilePath "./Tools/procexp64.exe /accepteula"
Start-Process -FilePath "./Tools/tcpview64.exe /accepteula"
Start-Process -FilePath "./Tools/wiztree/Wiztree64.exe"
Start-Process (Get-Process -Id $PID).Path -ArgumentList @("")

# Run PersistanceSniper

# Start a PingCastle Scan