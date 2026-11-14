<#
1600 - Spirit Shielding

AD Compromise Response

Rotate all user passwords
    
#>
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
Write-Output "Paste the domain user list from Quotient into a spreadsheet and then into DCPCRFormat.txt, hit any button to continue..."
Read-Host

if (!(Test-Path ".\\DCPCRFormat.txt")) {
    Write-Output "DCPCRFormat.txt doesn't exist? Did you delete it? WTF :( " "error"
    exit 1
}
$scoredDomainUserList = @()
$lastSeenUsersList = @()
$criticalBuiltinUsers = @("admin")

try 
{
    # Read from DCPCRformat.txt, assuming each line is username(whitespace)password
    $users = Get-Content ".\\DCPCRFormat.txt"
    foreach ($line in $users) {
        $splitline = -split $line
        $user = $splitline[0]
        $password = $splitline[1]
        Write-Output "Scored User: $user : $password"
        $scoredDomainUserList += $user
    }
}
catch {
    Write-Output "Something went wrong :(" "error"
    Write-Host $_.ScriptStackTrace
    exit 1
}

# Get all AD Users
$allDomainUsers = Get-ADUser -Filter *

# Load all previously seen users from lastseenusers.txt and clear it for new writes
try 
{
    # Read from lastseenusers.txt, assume each line is a unique user
    $lastSeenUsers = Get-Content ".\\lastseenusers.txt"
    foreach ($u in $lastSeenUsers) {
        if ($u -eq "NULL") {
            break
        }
        $lastSeenUsersList += $line
    }
    Clear-Content ".\\lastseenusers.txt"
}
catch {
    Write-Output "Something went wrong :(" "error"
    Write-Host $_.ScriptStackTrace
    exit 1
}
# Clear contents of DCPCRPaste for new writes

Clear-Content ".\\DCPCRPaste.txt"

# Generates comical PWs for each user with (New-Guid | Select-Object -Expand Guid) * 2

foreach ($domainUser in $allDomainUsers) {
    
    # Field Repairs: If the PCR format is different from just the Sam Account Name, change it to use one of the ones here
    # $username = $domainUser | Select-Object -Expand userPrincipalName # account@closedai.com
    # $username = "CLOSEDAI\\$($domainUser | Select-Object -Expand SamAccountName)" # CLOSEDAI\account

    $username = $domainUser | Select-Object -Expand SamAccountName
    if (-not $lastSeenUsersList -contains $username) {
        Write-Output "New Active Directory user $username?" "warn"
        Get-ADUser -Identity $username
    }
    # Skip all this pretty destructive UA for critical user accounts
    if ($criticalBuiltinUsers -contains $username) {
        Write-Output "Skipping User Auditing for user $username..." "info"
        continue
    }

    Write-Output "Changing password of $username..."
    $npw = ConvertTo-SecureString -String (New-Guid | Select-Object -Expand Guid) * 2 -AsPlainText -Force
    Set-ADAccountPassword -Identity $domainUser.SamAccountName -Reset -NewPassword $npw
    Write-Output "$username password successfully changed!" "success"
    if ($scoredDomainUserList -contains $username) {
        Write-Output "$username is a scored user, adding changed PW to DCPCRPaste..."
        Add-Content ".\\DCPCRPaste.txt" -Value "$username,$npw"
    } else {
        Set-Account
        if ($aggro -eq "nc") {
            $aggro = Read-Host "Aggressively disable unscored users? (Detected $username as a unscored user) (y/N)"
        }
        if ($aggro -eq "y") {
            Disable-ADAccount -Identity $username
            Write-Output "Disabled $username user account." "success"
        } else {
            Write-Output "Detected unscored user $username?" "warn"
        }
    }
}
# Perform AD User Auditing exactly like my UA+ script
