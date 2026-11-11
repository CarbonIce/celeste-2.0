<#
3200 - Dispel Magic
AD User Auditing Script

Meant for use on the DC only.
Requires the ActiveDirectory PowerShell module.

WARNING:
- Resets passwords for domain users.
- Can disable unscored accounts.
- Can modify sensitive AD account controls.
- DCPCRPaste.txt contains plaintext passwords.
#>

# ============================================================
# CONFIGURATION
# ============================================================

# Accounts exempt from password rotation and auditing remediation.
$criticalBuiltinUsers = @(
    "admin"
)

# Accounts authorized to belong to privileged groups.
# Populate this with authorized SamAccountNames.
$legalAdmins = @(
    # "Administrator"
    # "admin"
)

# Automatically remediate relatively safe account settings.
$autosafe = $true

# Automatically remediate sensitive delegation settings.
$autodanger = $false

# Password rotation is the primary purpose of this script.
$performPasswordResets = $true

# Automatically disable unscored accounts without prompting.
$disableUnscoredUsers = $false

# ============================================================
# USER ACCOUNT CONTROL FLAGS
# ============================================================

$logonScriptWillRun = 1
$accountDisabled = 2
$passwordNotRequired = 32
$reversibleEncryption = 128
$dontExpirePassword = 65536
$smartCardRequired = 262144
$desEncryptionOnly = 2097152
$doNotRequirePreauth = 4194304

# ============================================================
# OUTPUT FUNCTION
# ============================================================

function Write-Output {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Text,

        [ValidateSet("none", "info", "warn", "error", "success")]
        [string]$Code = "none"
    )

    switch ($Code) {
        "info" {
            $color = "Cyan"
            $symbol = "*"
        }
        "warn" {
            $color = "Yellow"
            $symbol = "!"
        }
        "error" {
            $color = "Red"
            $symbol = "X"
        }
        "success" {
            $color = "Green"
            $symbol = "+"
        }
        default {
            $color = "White"
            $symbol = "*"
        }
    }

    Write-Host "[$symbol] $Text" -ForegroundColor $color
}

# ============================================================
# INITIALIZATION
# ============================================================

$scoredDomainUserList = @()
$previousUsers = @{}
$currentUsers = @{}
$aggro = $null

$inputPath = ".\DCPCRFormat.txt"
$lastSeenPath = ".\lastseenusers.txt"
$pastePath = ".\DCPCRPaste.txt"

Write-Output "Dispel Magic - AD User Auditing" "info"

Write-Output "This script is intended to run on a Domain Controller." "warn"
Write-Output "Password rotation: $performPasswordResets"
Write-Output "Automatic safe remediation: $autosafe"
Write-Output "Automatic dangerous remediation: $autodanger"

if ($performPasswordResets) {
    Write-Output "WARNING: Domain user passwords will be reset!" "warn"
}

Write-Output "Paste the domain user list from Quotient into a spreadsheet, then into DCPCRFormat.txt."
Write-Output "Expected format: username whitespace password"
Write-Output "Press Enter to continue..." "info"

Read-Host

# Verify required files and environment.

if (!(Test-Path $inputPath)) {
    Write-Output "$inputPath does not exist!" "error"
    exit 1
}

if (!(Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Output "The ActiveDirectory PowerShell module is unavailable!" "error"
    exit 1
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Output "Failed to import ActiveDirectory module: $_" "error"
    exit 1
}

# ============================================================
# READ SCORED USERS
# ============================================================

try {
    $users = Get-Content $inputPath -ErrorAction Stop

    foreach ($line in $users) {

        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $splitLine = $line.Trim() -split '\s+'

        if ($splitLine.Count -lt 1 -or
            [string]::IsNullOrWhiteSpace($splitLine[0])) {

            Write-Output "Malformed entry in DCPCRFormat.txt: $line" "warn"
            continue
        }

        $username = $splitLine[0]

        # Passwords from the input file are deliberately not
        # printed to the console or retained in memory.

        $scoredDomainUserList += $username

        Write-Output "Scored user: $username" "info"
    }

    $scoredDomainUserList = $scoredDomainUserList | Select-Object -Unique

    Write-Output "Loaded $($scoredDomainUserList.Count) scored users." "success"
}
catch {
    Write-Output "Failed to read DCPCRFormat.txt: $_" "error"
    exit 1
}

# ============================================================
# LOAD PREVIOUSLY SEEN USERS
# ============================================================

if (Test-Path $lastSeenPath) {

    try {
        $lastSeenUsers = Get-Content $lastSeenPath -ErrorAction Stop

        foreach ($entry in $lastSeenUsers) {

            if ([string]::IsNullOrWhiteSpace($entry)) {
                continue
            }

            $parts = $entry.Trim() -split '\s+', 2

            if ($parts.Count -eq 2) {
                $previousUsers[$parts[0]] = $parts[1]
            }
        }

        Write-Output "Loaded $($previousUsers.Count) previously seen users." "success"
    }
    catch {
        Write-Output "Failed to read lastseenusers.txt: $_" "error"
        exit 1
    }
}
else {
    Write-Output "lastseenusers.txt does not exist. Creating it." "warn"
}

# Initialize output files.

try {
    Set-Content -Path $pastePath -Value "" -ErrorAction Stop
}
catch {
    Write-Output "Failed to initialize DCPCRPaste.txt: $_" "error"
    exit 1
}

# ============================================================
# RETRIEVE DOMAIN USERS
# ============================================================

try {
    $allDomainUsers = Get-ADUser -Filter * -Properties Enabled -ErrorAction Stop
}
catch {
    Write-Output "Failed to retrieve domain users: $_" "error"
    exit 1
}

Write-Output "Retrieved $($allDomainUsers.Count) domain users." "success"

# ============================================================
# PASSWORD ROTATION AND USER AUDITING
# ============================================================

foreach ($domainUser in $allDomainUsers) {

    $username = $domainUser.SamAccountName

    # Skip critical accounts.
    if ($criticalBuiltinUsers -contains $username) {
        Write-Output "Skipping critical user $username." "warn"
        continue
    }

    # Record current account status.
    if ($domainUser.Enabled) {
        $currentStatus = "ON"
    }
    else {
        $currentStatus = "OFF"
    }

    $currentUsers[$username] = $currentStatus

    # Compare with previous execution.
    if (!$previousUsers.ContainsKey($username)) {
        Write-Output "Newly detected user: $username" "info"
    }
    elseif ($previousUsers[$username] -ne $currentStatus) {
        Write-Output "$username changed status: $($previousUsers[$username]) -> $currentStatus" "warn"
    }

    # Password rotation.
    if ($performPasswordResets) {
        try {
            

            if ($scoredDomainUserList -contains $username) {
                
                Write-Output "Changing password of $username..."
                # Generate a random 72-character password.
                $plainPassword = ([guid]::NewGuid().Guid) +
                                ([guid]::NewGuid().Guid)

                $securePassword = ConvertTo-SecureString `
                    -String $plainPassword `
                    -AsPlainText `
                    -Force

                Set-ADAccountPassword `
                    -Identity $domainUser.SamAccountName `
                    -Reset `
                    -NewPassword $securePassword `
                    -ErrorAction Stop

                Write-Output "$username password successfully changed!" "success"

                Write-Output "Adding $username's password to DCPCRPaste.txt."

                # Intentionally plaintext for Quotient submission.
                Add-Content -Path $pastePath `
                    -Value "$username,$plainPassword" `
                    -ErrorAction Stop
            }
            else {

                Write-Output "$username is NOT a scored user." "warn"

                if ($null -eq $aggro -and !$disableUnscoredUsers) {

                    $aggro = Read-Host "Aggressively disable unscored users? (y/N)"

                    if ($aggro -notmatch '^(?i)y$') {
                        $aggro = "n"
                    }
                }

                if ($disableUnscoredUsers -or $aggro -eq "y") {

                    try {
                        Disable-ADAccount `
                            -Identity $username `
                            -ErrorAction Stop

                        Write-Output "Disabled $username." "success"

                    }
                    catch {
                        Write-Output "Failed to disable $username : $_" "error"
                    }

                }
                else {
                    Write-Output "Leaving unscored account $username enabled." "warn"
                }
            }

        }
        catch {
            Write-Output "Failed to reset password for $username : $_" "error"
        }
        finally {
            $plainPassword = $null
            $securePassword = $null
        }
    }
}

# ============================================================
# UPDATE LAST SEEN USERS
# ============================================================

try {

    $lastSeenOutput = foreach ($username in $currentUsers.Keys) {
        "$username $($currentUsers[$username])"
    }

    Set-Content -Path $lastSeenPath `
        -Value $lastSeenOutput `
        -ErrorAction Stop

    Write-Output "Updated lastseenusers.txt." "success"

}
catch {
    Write-Output "Failed to update lastseenusers.txt: $_" "error"
}

# ============================================================
# OPEN PASSWORD OUTPUT
# ============================================================

if ($performPasswordResets) {

    Write-Output "Opening password output for Quotient submission." "info"

    if ((Get-Item $pastePath).Length -gt 0) {

        Start-Process -FilePath "notepad.exe" -ArgumentList $pastePath

        Write-Output "DCPCRPaste.txt contains plaintext passwords. Protect this file!" "warn"

    }
    else {
        Write-Output "No scored passwords were written to DCPCRPaste.txt." "warn"
    }
}

# ============================================================
# ACCOUNT ATTRIBUTE AUDITING
# ============================================================

Write-Output "Checking specific account settings..." "info"

try {

    $accountsWithSettings = Get-ADUser `
        -Filter * `
        -Properties UserAccountControl,
                    TrustedToAuthForDelegation,
                    TrustedForDelegation,
                    LockedOut,
                    PasswordNeverExpires `
        -ErrorAction Stop

}
catch {
    Write-Output "Failed to retrieve account settings: $_" "error"
    exit 1
}

foreach ($user in $accountsWithSettings) {

    $username = $user.SamAccountName
    $uac = [int]$user.UserAccountControl

    # Reversible password encryption.
    if ($uac -band $reversibleEncryption) {

        Write-Output "$username allows reversible password encryption!" "warn"

        if ($autosafe) {
            try {
                Set-ADAccountControl `
                    -Identity $user `
                    -AllowReversiblePasswordEncryption $false `
                    -ErrorAction Stop

                Write-Output "Disabled reversible encryption for $username." "success"
            }
            catch {
                Write-Output "Failed to remediate $username : $_" "error"
            }
        }
    }

    # Kerberos preauthentication.
    if ($uac -band $doNotRequirePreauth) {

        Write-Output "$username does not require Kerberos preauthentication!" "warn"

        if ($autosafe) {
            try {
                Set-ADAccountControl `
                    -Identity $user `
                    -DoesNotRequirePreAuth $false `
                    -ErrorAction Stop

                Write-Output "Restored Kerberos preauthentication for $username." "success"
            }
            catch {
                Write-Output "Failed to remediate $username : $_" "error"
            }
        }
    }

    # DES-only encryption.
    if ($uac -band $desEncryptionOnly) {

        Write-Output "$username uses only DES encryption types!" "warn"

        if ($autosafe) {
            try {
                Set-ADAccountControl `
                    -Identity $user `
                    -UseDESKeyOnly $false `
                    -ErrorAction Stop

                Write-Output "Disabled DES-only encryption for $username." "success"
            }
            catch {
                Write-Output "Failed to remediate $username : $_" "error"
            }
        }
    }

    # Password never expires.
    if ($uac -band $dontExpirePassword) {

        Write-Output "$username's password never expires!" "warn"

        if ($autosafe) {
            try {
                Set-ADAccountControl `
                    -Identity $user `
                    -PasswordNeverExpires $false `
                    -ErrorAction Stop

                Write-Output "Enabled password expiration for $username." "success"
            }
            catch {
                Write-Output "Failed to remediate $username : $_" "error"
            }
        }
    }

    # Password not required.
    if ($uac -band $passwordNotRequired) {

        Write-Output "$username does not require a password!" "warn"

        try {
            Set-ADAccountControl `
                -Identity $user `
                -PasswordNotRequired $false `
                -ErrorAction Stop

            Write-Output "Enabled password requirement for $username." "success"
        }
        catch {
            Write-Output "Failed to remediate $username : $_" "error"
        }
    }

    # Trusted to authenticate for delegation.
    if ($user.TrustedToAuthForDelegation) {

        Write-Output "$username has protocol transition delegation enabled!" "warn"

        if ($autodanger) {
            try {
                Set-ADAccountControl `
                    -Identity $user `
                    -TrustedToAuthForDelegation $false `
                    -ErrorAction Stop

                Write-Output "Disabled protocol transition delegation for $username." "success"
            }
            catch {
                Write-Output "Failed to remediate $username : $_" "error"
            }
        }
    }

    # Trusted for delegation.
    if ($user.TrustedForDelegation) {

        Write-Output "$username is trusted for delegation!" "warn"

        if ($autodanger) {
            try {
                Set-ADAccountControl `
                    -Identity $user `
                    -TrustedForDelegation $false `
                    -ErrorAction Stop

                Write-Output "Disabled unconstrained delegation for $username." "success"
            }
            catch {
                Write-Output "Failed to remediate $username : $_" "error"
            }
        }
    }

    # Account state.
    if ($uac -band $accountDisabled) {
        Write-Output "$username is disabled." "info"
    }

    if ($user.LockedOut) {
        Write-Output "$username is locked out." "warn"
    }

    if ($uac -band $smartCardRequired) {
        Write-Output "$username requires a smart card for interactive logon." "info"
    }

    if ($uac -band $logonScriptWillRun) {
        Write-Output "$username has a logon script configured." "info"
    }
}

# ============================================================
# PRIVILEGED GROUP AUDITING
# ============================================================

Write-Output "Checking privileged group memberships..." "info"

$privilegedGroups = @(
    "Enterprise Admins",
    "Domain Admins",
    "Schema Admins",
    "DnsAdmins"
)

foreach ($groupName in $privilegedGroups) {

    try {

        $members = Get-ADGroupMember `
            -Identity $groupName `
            -ErrorAction Stop

        foreach ($member in $members) {

            $memberName = $member.SamAccountName

            if ([string]::IsNullOrWhiteSpace($memberName)) {
                $memberName = $member.Name
            }

            if ($legalAdmins -notcontains $memberName) {

                Write-Output "Possible unauthorized $groupName member: $memberName" "warn"
            }
            else {
                Write-Output "Authorized $groupName member: $memberName" "success"
            }
        }

    }
    catch {
        Write-Output "Could not retrieve members of $groupName : $_" "warn"
    }
}

# ============================================================
# ADMINISTRATIVE GROUP MANAGEMENT AUDITING
# ============================================================

Write-Output "Checking administrative group managers..." "info"

try {

    $adminGroups = Get-ADGroup `
        -Filter 'Name -like "*Admins"' `
        -Properties Name, ManagedBy `
        -ErrorAction Stop

    foreach ($group in $adminGroups) {

        if ($null -ne $group.ManagedBy) {

            try {

                $friendlyObject = Get-ADObject `
                    -Identity $group.ManagedBy `
                    -Properties Name `
                    -ErrorAction Stop

                Write-Output "$($group.Name) is managed by $($friendlyObject.Name)." "warn"

                if ($autodanger) {

                    Set-ADGroup `
                        -Identity $group `
                        -Clear ManagedBy `
                        -ErrorAction Stop

                    Write-Output "Removed manager from $($group.Name)." "success"
                }

            }
            catch {
                Write-Output "Failed to inspect or remediate manager for $($group.Name): $_" "error"
            }
        }
    }

}
catch {
    Write-Output "Failed to retrieve administrative groups: $_" "error"
}

# ============================================================
# COMPLETION
# ============================================================

Write-Output "Dispel Magic execution completed." "success"
Write-Output "Review all warnings and errors before considering the domain secured." "info"