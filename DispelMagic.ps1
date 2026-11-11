<# 3200 - Dispel Magic

AD User Auditing Script

Meant for use on the DC only

#>
$logonScriptWillRun = 1            # 1 indicates "Logon script will run"
$accountDisabled = 2               # 2 indicates "Account is disabled"
$accountLockedOut = 16             # 16 indicates "Account is locked out"
$passwordNotRequired = 32          # 32 indicates "Password not required"
$disallowChangePassword = 64       # 64 indicates "User cannot change password"
$reversibleEncryption = 128        # "Allow Reversable encryption"
$dontExpirePassword = 65536        # 65536 indicates "Password never expires"
$desEncryptionOnly = 2097152       # 2097152 indicates "Use only DES encryption types for this account"
$smartCardRequired = 262144        # 262144 indicates "Smart card is required for interactive logon"
$doNotRequirePreauth = 4194304     # 4194304 indicates "Do not require Kerberos preauthentication"

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

    # Skip all this pretty destructive UA for critical user accounts
    if ($criticalBuiltinUsers -contains $username) {
        Write-Output "Skipping User Auditing for user $username..." "warn"
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
    
    # Dispel Magic should only run once at the start of the comp; write all user accounts on the domain to lastseenusers.txt
    if ($domainUser.Enabled){
        Add-Content ".\\lastseenusers.txt" -Value "$username ON"
    } else {
        Add-Content ".\\lastseenusers.txt" -Value "$username OFF"
    }

}

# Open the PCR in a notepad to paste into Quotient
Start-Process -Path "notepad ./DCPCRPaste.txt"

# Check user attributes to ensure nothing insecure is set
$accountsWithSettings = Get-ADUser -Filter * -Properties SamAccountName, DisplayName, UserAccountControl, TrustedToAuthForDelegation, TrustedForDelegation, DistinguishedName

Write-Output "Checking more specific account settings..."

# Display the list of user accounts with specified settings
foreach ($user in $accountsWithSettings) {
    if ($user.UserAccountControl -band $reversibleEncryption) {
        Write-Output "$($user.SamAccountName) stores password using reversible encryption!" "warn"
        Write-Output "Resetting..."
        Set-ADAccountControl -Identity $user.SamAccountName -AllowReversiblePasswordEncryption $false
    }
    if ($user.UserAccountControl -band $doNotRequirePreauth) {
        Write-Host "[!] $($user.SamAccountName) does not require Kerberos Preauthentication!"
        Write-Host "Resetting..."
        Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth $false
    }
    if ($user.UserAccountControl -band $desEncryptionOnly) {
        Write-Host "[!] $($user.SamAccountName) uses only DES encryption types!"
        if ($autosafe){
            Write-Host "Resetting..."
            Set-ADAccountControl -Identity $user.SamAccountName -UseDESKeyOnly $false
        }
    }
    if ($user.UserAccountControl -band $dontExpirePassword) {
        Write-Host "[!] $($user.SamAccountName)'s password never expires!"
        if ($autosafe){
            Write-Host "Resetting..."
            Set-ADAccountControl -Identity $user.SamAccountName -PasswordNeverExpires $false
        }
    }
    if ($user.UserAccountControl -band $passwordNotRequired) {
        Write-Host "[!] $($user.SamAccountName) does not require a password!"
        Write-Host "Resetting..."
        Set-ADAccountControl -Identity $user.SamAccountName -PasswordNotRequired $false
    }
    if ($user.TrustedToAuthForDelegation) {
        Write-Host "[?!] $($user.SamAccountName) can delegate accounts? This is a very sensitive privilege."
        if ($autodanger){
            Write-Host "Resetting..."
            Set-ADAccountControl -Identity $user.SamAccountName -TrustedToAuthForDelegation $false
        }
    }
    if ($user.TrustedForDelegation) {
        Write-Host "[?] $($user.SamAccountName) can be delegated. This should not be set for sensitive accounts."
        if ($autodanger){
            Write-Host "Resetting..."
            Set-ADAccountControl -Identity $user.SamAccountName -TrustedForDelegation $false
        }
    }
    if ($user.UserAccountControl -band $accountDisabled) {
        Write-Host "[?] $($user.SamAccountName) is disabled."
    }
    if ($user.UserAccountControl -band $accountLockedOut) {
        Write-Host "[?] $($user.SamAccountName) is locked out."
    }
    if ($user.UserAccountControl -band $smartCardRequired) {
        Write-Host "[?] $($user.SamAccountName) requires a smart card for interactive logon."
    }
    if ($user.UserAccountControl -band $disallowChangePassword) {
        Write-Host "[?] $($user.SamAccountName) cannot change their password."
    }
    if ($user.UserAccountControl -band $logonScriptWillRun) {
        Write-Host "[?] $($user.SamAccountName)'s logon script will run."
    }
}

$enterpriseAdmins = Get-ADGroupMember "Enterprise Admins"
$domainAdmins = Get-ADGroupMember "Domain Admins"
$schemaAdmins = Get-ADGroupMember "Schema Admins"

# Retrieve DNS Admins if needed
$dnsAdmins = Get-ADGroupMember "DnsAdmins"

foreach ($schemaAdmin in $schemaAdmins) {
    $schemaAdminName = $schemaAdmin.Name
    if (!($legalAdmins -contains $schemaAdminName)) {
        Write-Host "[!] Possible unauthorized schema admin: $schemaAdminName"
    }
}

foreach ($admin in $enterpriseAdmins) {
    $adminName = $admin.SamAccountName
    if (!($legalAdmins -contains $adminName)) {
        Write-Host "[!] Possible unauthorized Enterprise Admin: $adminName"
    }
}

foreach ($admin in $domainAdmins) {
    $adminName = $admin.SamAccountName
    if (!($legalAdmins -contains $adminName)) {
        Write-Host "[!] Possible unauthorized Domain Admin: $adminName"
    }
}

# Check DNS Admins if needed
foreach ($admin in $dnsAdmins) {
    $adminName = $admin.SamAccountName
    if (!($legalAdmins -contains $adminName)) {
        Write-Host "[!] Possible unauthorized DNS Admin: $adminName"
    }
}

$adminGroups = Get-ADGroup -Filter { Name -like "*Admins" } -Properties Name,managedby
foreach ($group in $adminGroups) {
    $groupName = $group.Name
    $groupisManagedBy = $group.managedby
    if($null -ne $groupisManagedBy){
        $friendlyObjectName =  Get-ADObject -Filter { DistinguishedName -eq $groupIsManagedBy }
        Write-Host "[?!] $groupName is managed by $($friendlyObjectName.Name)?"
        if ($autodanger){
            Write-Host "Removing manager..."
            Set-ADGroup -Identity $group -ManagedBy $null
        }
    }
}