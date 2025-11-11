# Active Directory Enumeration - PowerShell Commands (No Module Required)

Complete Active Directory enumeration using pure PowerShell without requiring any modules. All commands use ADSI/LDAP/.NET framework classes that are built into Windows.

> **Note**: Based on 100+ BloodHound CE custom queries converted to PowerShell

---

## Table of Contents

1. [Domain Information](#domain-information)
2. [User Enumeration](#user-enumeration)
3. [Group Enumeration](#group-enumeration)
4. [Computer Enumeration](#computer-enumeration)
5. [Kerberos Attacks](#kerberos-attacks)
6. [Delegation](#delegation)
7. [ACL & Permissions](#acl--permissions)
8. [GPO Enumeration](#gpo-enumeration)
9. [AD CS (Certificate Services)](#ad-cs-certificate-services)
10. [Cross-Domain Attacks](#cross-domain-attacks)
11. [Helper Functions](#helper-functions)

---

## Domain Information

### Get Current Domain

```powershell
# Get current domain object
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Get domain name
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name

# Get domain DN
"DC=" + (([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name -replace "\.", ",DC=")
```

### Get Domain Controllers

```powershell
# List all domain controllers
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).DomainControllers

# Get DC details
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domain.DomainControllers | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        IPAddress = $_.IPAddress
        Site = $_.SiteName
        OSVersion = $_.OSVersion
    }
}
```

### Get Domain SID

```powershell
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")
$domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
$sid = New-Object System.Security.Principal.SecurityIdentifier($domainEntry.objectSid[0], 0)
$sid.Value
```

### Get Forest Information

```powershell
$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$forest | Select-Object Name, RootDomain, Sites, Domains, GlobalCatalogs
```

### Get Domain Trusts

```powershell
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domain.GetAllTrustRelationships() | Format-Table TargetName, TrustDirection, TrustType
```

---

## User Enumeration

### Get All Users

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=user)"
$searcher.PageSize = 1000
$users = $searcher.FindAll()
$users.Count
```

### Get Enabled Users Only

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$searcher.PageSize = 1000
$enabledUsers = $searcher.FindAll()
$enabledUsers.Count
```

### Get User Details

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(samAccountName=USERNAME))"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","distinguishedname","memberof","admincount","pwdlastset"))
$result = $searcher.FindOne()
$result.Properties
```

### Get Privileged Users (AdminCount=1)

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(adminCount=1))"
$searcher.PageSize = 1000
$privilegedUsers = $searcher.FindAll()

foreach ($user in $privilegedUsers) {
    [PSCustomObject]@{
        SamAccountName = $user.Properties.samaccountname[0]
        DistinguishedName = $user.Properties.distinguishedname[0]
        Description = if ($user.Properties.description) { $user.Properties.description[0] } else { "" }
    }
}
```

### Get Kerberoastable Users (SPN Set)

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","pwdlastset"))

$spnUsers = $searcher.FindAll()
foreach ($user in $spnUsers) {
    if ($user.Properties.samaccountname[0] -ne "krbtgt") {
        Write-Host "User: $($user.Properties.samaccountname[0])"
        foreach ($spn in $user.Properties.serviceprincipalname) {
            Write-Host "  SPN: $spn"
        }
    }
}
```

### Get AS-REP Roastable Users (Pre-Auth Not Required)

```powershell
# DONT_REQ_PREAUTH = 0x400000 (4194304)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$searcher.PageSize = 1000
$asrepUsers = $searcher.FindAll()

foreach ($user in $asrepUsers) {
    $uac = [int]$user.Properties.useraccountcontrol[0]
    $enabled = -not ($uac -band 2)
    if ($enabled) {
        Write-Host $user.Properties.samaccountname[0]
    }
}
```

### Get Users with Password Never Expires

```powershell
# DONT_EXPIRE_PASSWORD = 0x10000 (65536)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
$searcher.PageSize = 1000
$neverExpireUsers = $searcher.FindAll()

foreach ($user in $neverExpireUsers) {
    $uac = [int]$user.Properties.useraccountcontrol[0]
    $enabled = -not ($uac -band 2)
    if ($enabled) {
        Write-Host $user.Properties.samaccountname[0]
    }
}
```

### Get Users with Password Not Required

```powershell
# PASSWD_NOTREQD = 0x20 (32)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
$searcher.PageSize = 1000
$pwdNotReqUsers = $searcher.FindAll()

foreach ($user in $pwdNotReqUsers) {
    Write-Host "[!] $($user.Properties.samaccountname[0])"
}
```

### Get Users with Reversible Encryption

```powershell
# ENCRYPTED_TEXT_PWD_ALLOWED = 0x80 (128)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))"
$searcher.PageSize = 1000
$reversibleUsers = $searcher.FindAll()

foreach ($user in $reversibleUsers) {
    Write-Host "[!] $($user.Properties.samaccountname[0])"
}
```

### Get Users with SID History

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(sidHistory=*))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","sidhistory"))

$sidHistoryUsers = $searcher.FindAll()
foreach ($user in $sidHistoryUsers) {
    Write-Host "User: $($user.Properties.samaccountname[0])"
    foreach ($sid in $user.Properties.sidhistory) {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid, 0)
        Write-Host "  SID History: $($sidObj.Value)"
    }
}
```

### Get Users with Password in Description

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(|(description=*pass*)(description=*pwd*)(description=*password*)))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","description"))

$users = $searcher.FindAll()
foreach ($user in $users) {
    Write-Host "User: $($user.Properties.samaccountname[0])"
    Write-Host "  Description: $($user.Properties.description[0])"
}
```

### Get Disabled Users

```powershell
# ACCOUNTDISABLE = 0x2 (2)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
$searcher.PageSize = 1000
$disabledUsers = $searcher.FindAll()
$disabledUsers.Count
```

### Get Recently Created Users (Last 30 Days)

```powershell
$date = (Get-Date).AddDays(-30).ToString("yyyyMMddHHmmss.0Z")
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(whenCreated>=$date))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","whencreated"))

$recentUsers = $searcher.FindAll()
foreach ($user in $recentUsers) {
    Write-Host "$($user.Properties.samaccountname[0]) - Created: $($user.Properties.whencreated[0])"
}
```

---

## Group Enumeration

### Get All Groups

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=group)"
$searcher.PageSize = 1000
$groups = $searcher.FindAll()
$groups.Count
```

### Get Domain Admins

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=group)(name=Domain Admins))"
$result = $searcher.FindOne()

if ($result.Properties.member) {
    foreach ($member in $result.Properties.member) {
        if ($member -match "CN=([^,]+)") {
            Write-Host $matches[1]
        }
    }
}
```

### Get Enterprise Admins

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=group)(name=Enterprise Admins))"
$result = $searcher.FindOne()

if ($result.Properties.member) {
    foreach ($member in $result.Properties.member) {
        if ($member -match "CN=([^,]+)") {
            Write-Host $matches[1]
        }
    }
}
```

### Get All Privileged Groups

```powershell
$privilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners"
)

foreach ($groupName in $privilegedGroups) {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=group)(name=$groupName))"
    $result = $searcher.FindOne()
    
    if ($result) {
        $memberCount = if ($result.Properties.member) { $result.Properties.member.Count } else { 0 }
        Write-Host "$groupName : $memberCount members"
    }
}
```

### Get Groups with Admin in Name

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=group)(name=*admin*))"
$searcher.PageSize = 1000
$adminGroups = $searcher.FindAll()

foreach ($group in $adminGroups) {
    $memberCount = if ($group.Properties.member) { $group.Properties.member.Count } else { 0 }
    Write-Host "$($group.Properties.samaccountname[0]) ($memberCount members)"
}
```

### Get Empty Groups

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=group)(!member=*))"
$searcher.PageSize = 1000
$emptyGroups = $searcher.FindAll()

foreach ($group in $emptyGroups) {
    Write-Host $group.Properties.samaccountname[0]
}
```

### Get Group Members

```powershell
$groupName = "Domain Admins"
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=group)(name=$groupName))"
$result = $searcher.FindOne()

if ($result.Properties.member) {
    foreach ($member in $result.Properties.member) {
        Write-Host $member
    }
}
```

### Get User's Group Memberships

```powershell
$username = "USERNAME"
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(samAccountName=$username))"
$result = $searcher.FindOne()

if ($result.Properties.memberof) {
    foreach ($group in $result.Properties.memberof) {
        if ($group -match "CN=([^,]+)") {
            Write-Host $matches[1]
        }
    }
}
```

---

## Computer Enumeration

### Get All Computers

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=computer)"
$searcher.PageSize = 1000
$computers = $searcher.FindAll()
$computers.Count
```

### Get Enabled Computers

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$searcher.PageSize = 1000
$enabledComputers = $searcher.FindAll()
$enabledComputers.Count
```

### Get Domain Controllers (by Primary Group ID)

```powershell
# Primary Group ID 516 = Domain Controllers
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(primaryGroupID=516))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("dnshostname","operatingsystem","samaccountname"))

$dcs = $searcher.FindAll()
foreach ($dc in $dcs) {
    Write-Host "DC: $($dc.Properties.dnshostname[0])"
    Write-Host "  OS: $($dc.Properties.operatingsystem[0])"
}
```

### Get Computers by Operating System

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=computer)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.Add("operatingsystem") | Out-Null

$computers = $searcher.FindAll()
$computers | Group-Object { $_.Properties.operatingsystem[0] } | Sort-Object Count -Descending | Format-Table Name, Count
```

### Get Servers

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(operatingSystem=*Server*))"
$searcher.PageSize = 1000
$servers = $searcher.FindAll()
$servers.Count
```

### Get Workstations

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(!(operatingSystem=*Server*)))"
$searcher.PageSize = 1000
$workstations = $searcher.FindAll()
$workstations.Count
```

### Get Computers without LAPS

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(!(primaryGroupID=516)))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","ms-Mcs-AdmPwd"))

$computers = $searcher.FindAll()
$noLAPS = $computers | Where-Object { 
    -not $_.Properties.'ms-mcs-admpwd'
}

Write-Host "Computers without LAPS: $($noLAPS.Count)"
```

### Get Computers with SQL SPNs

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(servicePrincipalName=*SQL*))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("dnshostname","serviceprincipalname"))

$sqlComputers = $searcher.FindAll()
foreach ($computer in $sqlComputers) {
    Write-Host "SQL Server: $($computer.Properties.dnshostname[0])"
    foreach ($spn in $computer.Properties.serviceprincipalname) {
        if ($spn -like "*SQL*") {
            Write-Host "  SPN: $spn"
        }
    }
}
```

### Get Recently Added Computers (Last 30 Days)

```powershell
$date = (Get-Date).AddDays(-30).ToString("yyyyMMddHHmmss.0Z")
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(whenCreated>=$date))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","whencreated"))

$recentComputers = $searcher.FindAll()
foreach ($computer in $recentComputers) {
    Write-Host "$($computer.Properties.samaccountname[0]) - Created: $($computer.Properties.whencreated[0])"
}
```

---

## Kerberos Attacks

### Find All Kerberoastable Users

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!(samAccountName=krbtgt)))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","memberof"))

$spnUsers = $searcher.FindAll()
foreach ($user in $spnUsers) {
    Write-Host "Target: $($user.Properties.samaccountname[0])"
    Write-Host "  SPNs:"
    foreach ($spn in $user.Properties.serviceprincipalname) {
        Write-Host "    - $spn"
    }
}
```

### Request Kerberos TGS Ticket (Kerberoasting)

```powershell
# For a specific SPN
Add-Type -AssemblyName System.IdentityModel
$SPN = "HTTP/webserver.domain.local"
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
```

### List Cached Kerberos Tickets

```powershell
klist
```

### Find AS-REP Roastable Accounts

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
$searcher.PageSize = 1000

$asrepUsers = $searcher.FindAll()
foreach ($user in $asrepUsers) {
    Write-Host "AS-REP Roastable: $($user.Properties.samaccountname[0])"
}
```

---

## Delegation

### Find Unconstrained Delegation (Computers)

```powershell
# TRUSTED_FOR_DELEGATION = 0x80000 (524288)
# Exclude Domain Controllers (primaryGroupID 516)
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("dnshostname","samaccountname"))

$unconstrainedComputers = $searcher.FindAll()
foreach ($computer in $unconstrainedComputers) {
    Write-Host "[!] $($computer.Properties.dnshostname[0])"
}
```

### Find Unconstrained Delegation (Users)

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
$searcher.PageSize = 1000

$unconstrainedUsers = $searcher.FindAll()
foreach ($user in $unconstrainedUsers) {
    Write-Host "[!] $($user.Properties.samaccountname[0])"
}
```

### Find Constrained Delegation

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=*)(msds-allowedtodelegateto=*))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","msds-allowedtodelegateto","useraccountcontrol"))

$constrainedObjects = $searcher.FindAll()
foreach ($obj in $constrainedObjects) {
    Write-Host "Object: $($obj.Properties.samaccountname[0])"
    Write-Host "  Allowed to delegate to:"
    foreach ($target in $obj.Properties.'msds-allowedtodelegateto') {
        Write-Host "    - $target"
    }
    
    # Check for Protocol Transition
    $uac = [int]$obj.Properties.useraccountcontrol[0]
    if ($uac -band 0x1000000) {
        Write-Host "  [!] Protocol Transition Enabled (T2A4D)"
    }
}
```

### Find Resource-Based Constrained Delegation (RBCD)

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("dnshostname","samaccountname"))

$rbcdComputers = $searcher.FindAll()
foreach ($computer in $rbcdComputers) {
    Write-Host "RBCD configured on: $($computer.Properties.dnshostname[0])"
}
```

---

## ACL & Permissions

### Get ACL for Object

```powershell
$dn = "CN=User,OU=Users,DC=domain,DC=local"
$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
$entry.ObjectSecurity.Access | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType
```

### Find Objects with Specific User/Group Having Permissions

```powershell
# This requires more complex ACL parsing
# Example: Check if a user has GenericAll on an object
$targetDN = "CN=Administrator,CN=Users,DC=domain,DC=local"
$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$targetDN")
$acl = $entry.ObjectSecurity.Access

foreach ($ace in $acl) {
    if ($ace.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner") {
        Write-Host "$($ace.IdentityReference) has $($ace.ActiveDirectoryRights)"
    }
}
```

### Check for WriteDACL Permissions

```powershell
$dn = "CN=User,OU=Users,DC=domain,DC=local"
$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
$entry.ObjectSecurity.Access | Where-Object {
    $_.ActiveDirectoryRights -match "WriteDacl"
} | Format-Table IdentityReference, ActiveDirectoryRights
```

---

## GPO Enumeration

### Get All GPOs

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=groupPolicyContainer)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("displayname","gpcfilesyspath"))

$gpos = $searcher.FindAll()
foreach ($gpo in $gpos) {
    Write-Host "GPO: $($gpo.Properties.displayname[0])"
    Write-Host "  Path: $($gpo.Properties.gpcfilesyspath[0])"
}
```

### Find GPOs with Specific Keywords

```powershell
$keywords = @("password", "admin", "credential", "firewall")
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=groupPolicyContainer)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.Add("displayname") | Out-Null

$gpos = $searcher.FindAll()
foreach ($gpo in $gpos) {
    $name = $gpo.Properties.displayname[0]
    foreach ($keyword in $keywords) {
        if ($name -like "*$keyword*") {
            Write-Host "[*] $name (contains: $keyword)"
            break
        }
    }
}
```

---

## AD CS (Certificate Services)

### Find Enterprise CAs

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=pKIEnrollmentService)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("name","dnshostname","certificatetemplates"))

$cas = $searcher.FindAll()
foreach ($ca in $cas) {
    Write-Host "CA: $($ca.Properties.name[0])"
    Write-Host "  Host: $($ca.Properties.dnshostname[0])"
    if ($ca.Properties.certificatetemplates) {
        Write-Host "  Templates: $($ca.Properties.certificatetemplates.Count)"
    }
}
```

### Find Certificate Templates

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=pKICertificateTemplate)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("name","displayname"))

$templates = $searcher.FindAll()
foreach ($template in $templates) {
    Write-Host "Template: $($template.Properties.name[0])"
}
```

### Find Potentially Vulnerable Certificate Templates (ESC1)

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=pKICertificateTemplate)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("name","mspki-certificate-name-flag","pkiextendedkeyusage"))

$templates = $searcher.FindAll()
foreach ($template in $templates) {
    $nameFlag = [int]$template.Properties.'mspki-certificate-name-flag'[0]
    
    # Check if ENROLLEE_SUPPLIES_SUBJECT (bit 0) is set
    if ($nameFlag -band 1) {
        # Check for Client Authentication EKU
        if ($template.Properties.pkiextendedkeyusage -contains "1.3.6.1.5.5.7.3.2") {
            Write-Host "[!] Potential ESC1: $($template.Properties.name[0])"
        }
    }
}
```

---

## Cross-Domain Attacks

### Find Foreign Security Principals

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=foreignSecurityPrincipal)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("distinguishedname","objectsid"))

$fsps = $searcher.FindAll()
Write-Host "Foreign Security Principals: $($fsps.Count)"
```

### Find Users with Foreign Domain Group Membership

```powershell
$currentDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
$currentDomainDN = "DC=" + ($currentDomain -replace "\.", ",DC=")

$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=user)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","memberof"))

$users = $searcher.FindAll()
foreach ($user in $users) {
    if ($user.Properties.memberof) {
        foreach ($group in $user.Properties.memberof) {
            if ($group -notmatch [regex]::Escape($currentDomainDN)) {
                Write-Host "User: $($user.Properties.samaccountname[0])"
                Write-Host "  Foreign Group: $group"
            }
        }
    }
}
```

---

## Helper Functions

### Create Directory Searcher

```powershell
function Get-DomainSearcher {
    param(
        [string]$Filter = "(objectClass=*)",
        [string[]]$Properties = @("*"),
        [int]$PageSize = 1000
    )
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = $Filter
    $searcher.PageSize = $PageSize
    
    foreach ($prop in $Properties) {
        $searcher.PropertiesToLoad.Add($prop) | Out-Null
    }
    
    return $searcher
}
```

### Convert LDAP Result to PSObject

```powershell
function Convert-LDAPResult {
    param($Result)
    
    $obj = New-Object PSObject
    foreach ($prop in $Result.Properties.PropertyNames) {
        $value = $Result.Properties[$prop]
        if ($value.Count -gt 1) {
            $obj | Add-Member -MemberType NoteProperty -Name $prop -Value @($value)
        } else {
            $obj | Add-Member -MemberType NoteProperty -Name $prop -Value $value[0]
        }
    }
    return $obj
}
```

### Convert FileTime to DateTime

```powershell
function ConvertFrom-FileTime {
    param([string]$FileTime)
    
    try {
        [DateTime]::FromFileTime([Int64]::Parse($FileTime))
    } catch {
        $null
    }
}
```

### Check if Account is Enabled

```powershell
function Test-AccountEnabled {
    param([int]$UserAccountControl)
    
    # ACCOUNTDISABLE = 0x2
    return -not ($UserAccountControl -band 2)
}
```

---

## UserAccountControl Flags

Common UAC flags for reference:

```powershell
$UACFlags = @{
    SCRIPT                         = 0x0001      # 1
    ACCOUNTDISABLE                 = 0x0002      # 2
    HOMEDIR_REQUIRED              = 0x0008      # 8
    LOCKOUT                       = 0x0010      # 16
    PASSWD_NOTREQD                = 0x0020      # 32
    PASSWD_CANT_CHANGE            = 0x0040      # 64
    ENCRYPTED_TEXT_PWD_ALLOWED    = 0x0080      # 128
    TEMP_DUPLICATE_ACCOUNT        = 0x0100      # 256
    NORMAL_ACCOUNT                = 0x0200      # 512
    INTERDOMAIN_TRUST_ACCOUNT     = 0x0800      # 2048
    WORKSTATION_TRUST_ACCOUNT     = 0x1000      # 4096
    SERVER_TRUST_ACCOUNT          = 0x2000      # 8192
    DONT_EXPIRE_PASSWORD          = 0x10000     # 65536
    MNS_LOGON_ACCOUNT            = 0x20000     # 131072
    SMARTCARD_REQUIRED           = 0x40000     # 262144
    TRUSTED_FOR_DELEGATION       = 0x80000     # 524288
    NOT_DELEGATED                = 0x100000    # 1048576
    USE_DES_KEY_ONLY             = 0x200000    # 2097152
    DONT_REQ_PREAUTH             = 0x400000    # 4194304
    PASSWORD_EXPIRED             = 0x800000    # 8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # 16777216
    PARTIAL_SECRETS_ACCOUNT      = 0x04000000  # 67108864
}
```

### Check UAC Flag

```powershell
function Test-UACFlag {
    param(
        [int]$UserAccountControl,
        [int]$Flag
    )
    
    return ($UserAccountControl -band $Flag) -ne 0
}

# Example usage:
# Test-UACFlag -UserAccountControl $uac -Flag 524288  # Check TRUSTED_FOR_DELEGATION
```

---

## Well-Known SIDs

```powershell
$WellKnownSIDs = @{
    'S-1-0-0'   = 'Null Authority'
    'S-1-1-0'   = 'Everyone'
    'S-1-5-11'  = 'Authenticated Users'
    'S-1-5-32-544' = 'Administrators'
    'S-1-5-32-545' = 'Users'
    'S-1-5-32-546' = 'Guests'
    'S-1-5-32-547' = 'Power Users'
    'S-1-5-32-548' = 'Account Operators'
    'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'
    'S-1-5-32-551' = 'Backup Operators'
    'S-1-5-32-552' = 'Replicators'
    'S-1-5-32-554' = 'Pre-Windows 2000 Compatible Access'
    'S-1-5-32-555' = 'Remote Desktop Users'
    'S-1-5-32-556' = 'Network Configuration Operators'
}

# Domain-specific SIDs (append domain SID):
# -512  Domain Admins
# -513  Domain Users
# -514  Domain Guests
# -515  Domain Computers
# -516  Domain Controllers
# -517  Cert Publishers
# -518  Schema Admins
# -519  Enterprise Admins
# -520  Group Policy Creator Owners
```

---

## LDAP Filters Quick Reference

### User Filters

```
# All users
(objectClass=user)

# Enabled users
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Disabled users
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))

# Privileged users
(&(objectClass=user)(adminCount=1))

# Users with SPN
(&(objectClass=user)(servicePrincipalName=*))

# AS-REP Roastable
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# Password never expires
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))

# Password not required
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))
```

### Computer Filters

```
# All computers
(objectClass=computer)

# Domain Controllers
(&(objectClass=computer)(primaryGroupID=516))

# Servers
(&(objectClass=computer)(operatingSystem=*Server*))

# Unconstrained delegation
(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))

# Constrained delegation
(&(objectClass=computer)(msds-allowedtodelegateto=*))
```

### Group Filters

```
# All groups
(objectClass=group)

# Specific group
(&(objectClass=group)(name=Domain Admins))

# Empty groups
(&(objectClass=group)(!member=*))
```

---

## Export Results to CSV

### Export All Users

```powershell
$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectClass=user)"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("samaccountname","distinguishedname","admincount","pwdlastset"))

$users = $searcher.FindAll()
$results = foreach ($user in $users) {
    [PSCustomObject]@{
        SamAccountName = $user.Properties.samaccountname[0]
        DistinguishedName = $user.Properties.distinguishedname[0]
        AdminCount = if ($user.Properties.admincount) { $user.Properties.admincount[0] } else { 0 }
        PwdLastSet = if ($user.Properties.pwdlastset) { 
            [DateTime]::FromFileTime([Int64]::Parse($user.Properties.pwdlastset[0]))
        } else { $null }
    }
}

$results | Export-Csv -Path ".\AD-Users.csv" -NoTypeInformation
```

---

## Tips & Best Practices

### 1. Use PageSize for Large Directories

Always set `PageSize` property when dealing with large AD environments:

```powershell
$searcher.PageSize = 1000
```

### 2. Limit Properties to Load

Only load properties you need:

```powershell
$searcher.PropertiesToLoad.AddRange(@("samaccountname","distinguishedname"))
```

### 3. Handle Null Values

Always check if properties exist:

```powershell
$description = if ($user.Properties.description) { 
    $user.Properties.description[0] 
} else { 
    "" 
}
```

### 4. Use Bitwise Operations for UAC

```powershell
# Check if account is disabled
$uac = [int]$user.Properties.useraccountcontrol[0]
$isDisabled = ($uac -band 2) -ne 0
```

### 5. Escape Special Characters in Filters

```powershell
$username = "user(test)"
$escapedName = $username -replace '([\\*()\x00])', '\$1'
$searcher.Filter = "(&(objectClass=user)(samAccountName=$escapedName))"
```

---

## Complete Enumeration Script

For the complete automated enumeration script with all queries, see:
**[AD-BloodHound-Queries-NoModule.ps1](./AD-BloodHound-Queries-NoModule.ps1)**

The script includes:
- ✅ All queries from this document
- ✅ Organized output with color coding
- ✅ Vulnerability detection
- ✅ CSV export functionality
- ✅ No module dependencies

---

## References

- [Microsoft LDAP Documentation](https://docs.microsoft.com/en-us/windows/win32/adsi/ldap-adspath)
- [UserAccountControl Flags](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)
- [BloodHound CE Documentation](https://support.bloodhoundenterprise.io/)
- [LDAP Filter Syntax](https://ldap.com/ldap-filters/)

---

## License

This documentation is provided for educational and authorized security testing purposes only.

---

*Last Updated: 2024*
