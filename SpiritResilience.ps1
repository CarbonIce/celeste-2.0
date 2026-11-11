<#

3200 - Spirit Resilience
(AD Security Preventative Measures)

Increase the functional level of the domain to WS 2016
Sets dSHeuristics to 0000000001000000000200000001130
Sets permissions on the adminSDHolder object
List all accounts in sensitive groups or have bad permissions
Save current list of Domain Users to a file
Disables NTLM authentication
Shuts down AD:CS entirely

#>

# Set dSHerustics

$dSObject = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)" -Properties dSHeuristics
$dSObject.Properties["dSHeuristics"] = "0000000001000000000200000001130"
$dSObject.commitChanges()

# Set permissions on the adminSDHolder object


