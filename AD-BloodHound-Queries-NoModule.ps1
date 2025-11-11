<#
.SYNOPSIS
    Active Directory BloodHound Query Equivalents - No Module Required
    
.DESCRIPTION
    PowerShell equivalents of all BloodHound CE queries using pure ADSI/LDAP/.NET
    No modules required - works with standard Windows PowerShell
    Based on 100+ BloodHound CE custom queries
    
.NOTES
    Author: AD Security Research
    Version: 1.0
    Requires: Domain-joined machine or credentials
    
.EXAMPLE
    .\AD-BloodHound-Queries-NoModule.ps1
    
.EXAMPLE
    # Use alternate credentials
    $cred = Get-Credential
    .\AD-BloodHound-Queries-NoModule.ps1 -Credential $cred
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$Server,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportCSV,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\AD-Enum-Results"
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Banner {
    $banner = @"

    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     Active Directory BloodHound Query Equivalents v1.0      ║
    ║              No Module Required - Pure ADSI/LDAP            ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Write-SectionHeader {
    param([string]$Text)
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  $Text" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Write-QueryHeader {
    param([string]$Text)
    Write-Host "`n[+] $Text" -ForegroundColor Yellow
    Write-Host ("─" * 70) -ForegroundColor DarkGray
}

function Write-Result {
    param(
        [string]$Text,
        [string]$Type = "Info"
    )
    $symbol = switch($Type) {
        "Vuln"    { "[!]"; $color = "Red" }
        "Warning" { "[*]"; $color = "Yellow" }
        "Success" { "[✓]"; $color = "Green" }
        "Info"    { "  •"; $color = "White" }
        default   { "  •"; $color = "White" }
    }
    Write-Host "$symbol $Text" -ForegroundColor $color
}

function Get-DomainSearcher {
    param(
        [string]$SearchBase,
        [string]$Filter = "(objectClass=*)",
        [string[]]$Properties = @("*"),
        [int]$PageSize = 1000
    )
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")
        
        if (!$SearchBase) {
            $SearchBase = $domainDN
        }
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
        $searcher.Filter = $Filter
        $searcher.PageSize = $PageSize
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        
        foreach ($prop in $Properties) {
            $null = $searcher.PropertiesToLoad.Add($prop)
        }
        
        if ($Credential) {
            $searcher.SearchRoot.Username = $Credential.UserName
            $searcher.SearchRoot.Password = $Credential.GetNetworkCredential().Password
        }
        
        return $searcher
    } catch {
        Write-Warning "Error creating directory searcher: $_"
        return $null
    }
}

function Convert-ADSIResult {
    param($Result)
    
    if (!$Result) { return $null }
    
    $obj = New-Object PSObject
    
    foreach ($prop in $Result.Properties.PropertyNames) {
        $value = $Result.Properties[$prop]
        
        # Handle multi-value properties
        if ($value.Count -gt 1) {
            $obj | Add-Member -MemberType NoteProperty -Name $prop -Value @($value)
        } elseif ($value.Count -eq 1) {
            $obj | Add-Member -MemberType NoteProperty -Name $prop -Value $value[0]
        } else {
            $obj | Add-Member -MemberType NoteProperty -Name $prop -Value $null
        }
    }
    
    return $obj
}

function Get-ADObjectAttribute {
    param(
        [string]$DistinguishedName,
        [string]$Attribute
    )
    
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DistinguishedName")
        if ($Credential) {
            $entry.Username = $Credential.UserName
            $entry.Password = $Credential.GetNetworkCredential().Password
        }
        
        return $entry.$Attribute.Value
    } catch {
        return $null
    }
}

function Test-ADObjectProperty {
    param(
        $ADObject,
        [string]$Property,
        $Value
    )
    
    try {
        $propValue = $ADObject.$Property
        if ($null -eq $propValue) { return $false }
        
        if ($Value -is [bool]) {
            return [bool]$propValue -eq $Value
        } else {
            return $propValue -eq $Value
        }
    } catch {
        return $false
    }
}

# ============================================================================
# DOMAIN ENUMERATION
# ============================================================================

function Get-DomainInfo {
    Write-SectionHeader "1. DOMAIN INFORMATION"
    
    Write-QueryHeader "Domain Overview"
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        
        Write-Result "Domain Name: $($domain.Name)" -Type "Success"
        Write-Result "NetBIOS Name: $($domain.Name.Split('.')[0])" -Type "Info"
        Write-Result "Forest Name: $($forest.Name)" -Type "Info"
        Write-Result "Domain Controllers: $($domain.DomainControllers.Count)" -Type "Info"
        
        # Get domain DN
        $domainDN = "DC=" + ($domain.Name -replace "\.", ",DC=")
        Write-Result "Domain DN: $domainDN" -Type "Info"
        
        # Get domain SID
        $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
        if ($domainEntry.objectSid) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($domainEntry.objectSid[0], 0)
            Write-Result "Domain SID: $($sid.Value)" -Type "Info"
        }
        
    } catch {
        Write-Result "Error retrieving domain info: $_" -Type "Warning"
    }
    
    Write-QueryHeader "Domain Controllers"
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        foreach ($dc in $domain.DomainControllers) {
            Write-Result "DC: $($dc.Name)" -Type "Success"
            Write-Result "  └─ IP Address: $($dc.IPAddress)" -Type "Info"
            Write-Result "  └─ Site: $($dc.SiteName)" -Type "Info"
            Write-Result "  └─ OS Version: $($dc.OSVersion)" -Type "Info"
            
            # Check if Global Catalog
            $searcher = Get-DomainSearcher -Filter "(&(objectClass=computer)(dNSHostName=$($dc.Name)))" -Properties @("msDS-IsGC", "operatingSystem")
            $result = $searcher.FindOne()
            if ($result) {
                $obj = Convert-ADSIResult $result
                if ($obj.'msds-isgc') {
                    Write-Result "  └─ Global Catalog: Yes" -Type "Info"
                }
                if ($obj.operatingsystem -match "2008|2003") {
                    Write-Result "  └─ [!] Outdated OS: $($obj.operatingsystem)" -Type "Vuln"
                }
            }
        }
    } catch {
        Write-Result "Error enumerating DCs: $_" -Type "Warning"
    }
    
    Write-QueryHeader "Domain Trusts"
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $trusts = $domain.GetAllTrustRelationships()
        
        if ($trusts.Count -gt 0) {
            foreach ($trust in $trusts) {
                Write-Result "Trust: $($trust.TargetName)" -Type "Success"
                Write-Result "  └─ Direction: $($trust.TrustDirection)" -Type "Info"
                Write-Result "  └─ Type: $($trust.TrustType)" -Type "Info"
                
                if ($trust.TrustDirection -eq "Bidirectional") {
                    Write-Result "  └─ [*] Bidirectional trust detected" -Type "Warning"
                }
            }
        } else {
            Write-Result "No external trusts found" -Type "Info"
        }
    } catch {
        Write-Result "No trusts or error: $_" -Type "Info"
    }
}

# ============================================================================
# USER ENUMERATION
# ============================================================================

function Get-AllUsers {
    Write-SectionHeader "2. USER ENUMERATION"
    
    Write-QueryHeader "User Statistics"
    $searcher = Get-DomainSearcher -Filter "(objectClass=user)" -Properties @(
        "samaccountname", "distinguishedname", "useraccountcontrol", "admincount",
        "serviceprincipalname", "pwdlastset", "lastlogontimestamp", "whencreated",
        "description", "memberof", "primarygroupid"
    )
    
    $allUsers = $searcher.FindAll()
    Write-Result "Total User Objects: $($allUsers.Count)" -Type "Success"
    
    # Filter enabled users
    $enabledUsers = $allUsers | Where-Object {
        $uac = [int]$_.Properties.useraccountcontrol[0]
        -not ($uac -band 2) # Not disabled
    }
    Write-Result "Enabled Users: $($enabledUsers.Count)" -Type "Info"
    Write-Result "Disabled Users: $(($allUsers.Count - $enabledUsers.Count))" -Type "Info"
    
    return @{
        All = $allUsers
        Enabled = $enabledUsers
    }
}

function Get-PrivilegedUsers {
    Write-QueryHeader "Privileged Users (AdminCount=1)"
    
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(adminCount=1))" -Properties @(
        "samaccountname", "distinguishedname", "description", "memberof", "useraccountcontrol"
    )
    
    $privilegedUsers = $searcher.FindAll()
    Write-Result "Users with AdminCount=1: $($privilegedUsers.Count)" -Type "Warning"
    
    foreach ($user in $privilegedUsers) {
        $obj = Convert-ADSIResult $user
        $uac = [int]$obj.useraccountcontrol
        $enabled = -not ($uac -band 2)
        
        $status = if ($enabled) { "[ENABLED]" } else { "[DISABLED]" }
        Write-Result "  • $status $($obj.samaccountname)" -Type "Info"
        if ($obj.description) {
            Write-Result "    └─ $($obj.description)" -Type "Info"
        }
    }
}

function Get-KerberoastableUsers {
    Write-QueryHeader "Kerberoastable Users (SPN Set)"
    
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(servicePrincipalName=*))" -Properties @(
        "samaccountname", "serviceprincipalname", "useraccountcontrol", "pwdlastset", "admincount"
    )
    
    $spnUsers = $searcher.FindAll()
    Write-Result "Kerberoastable Accounts: $($spnUsers.Count)" -Type "Warning"
    
    foreach ($user in $spnUsers) {
        $obj = Convert-ADSIResult $user
        
        # Skip krbtgt
        if ($obj.samaccountname -eq "krbtgt") { continue }
        
        $uac = [int]$obj.useraccountcontrol
        $enabled = -not ($uac -band 2)
        
        if ($enabled) {
            $adminStatus = if ([int]$obj.admincount -eq 1) { "[PRIVILEGED]" } else { "" }
            Write-Result "  • $adminStatus $($obj.samaccountname)" -Type "Warning"
            
            foreach ($spn in $obj.serviceprincipalname) {
                Write-Result "    └─ SPN: $spn" -Type "Info"
            }
            
            # Check password age
            if ($obj.pwdlastset) {
                $pwdAge = [DateTime]::FromFileTime([Int64]::Parse($obj.pwdlastset))
                $daysSinceChange = ((Get-Date) - $pwdAge).Days
                if ($daysSinceChange -gt 365) {
                    Write-Result "    └─ [!] Password not changed in $daysSinceChange days" -Type "Vuln"
                }
            }
        }
    }
}

function Get-ASREPRoastableUsers {
    Write-QueryHeader "AS-REP Roastable Users (Pre-Auth Not Required)"
    
    # UF_DONT_REQUIRE_PREAUTH = 0x400000 (4194304)
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties @(
        "samaccountname", "distinguishedname", "useraccountcontrol"
    )
    
    $asrepUsers = $searcher.FindAll()
    Write-Result "AS-REP Roastable Users: $($asrepUsers.Count)" -Type "Warning"
    
    foreach ($user in $asrepUsers) {
        $obj = Convert-ADSIResult $user
        $uac = [int]$obj.useraccountcontrol
        $enabled = -not ($uac -band 2)
        
        if ($enabled) {
            Write-Result "  • $($obj.samaccountname)" -Type "Warning"
        }
    }
}

function Get-PasswordIssues {
    Write-QueryHeader "Password Policy Violations"
    
    # Password Never Expires
    Write-Result "`nUsers with Password Never Expires:" -Type "Warning"
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -Properties @(
        "samaccountname", "useraccountcontrol"
    )
    $pwdNeverExpires = $searcher.FindAll()
    Write-Result "  Count: $($pwdNeverExpires.Count)" -Type "Info"
    
    foreach ($user in ($pwdNeverExpires | Select-Object -First 10)) {
        $obj = Convert-ADSIResult $user
        $uac = [int]$obj.useraccountcontrol
        $enabled = -not ($uac -band 2)
        if ($enabled) {
            Write-Result "  • $($obj.samaccountname)" -Type "Info"
        }
    }
    
    # Password Not Required
    Write-Result "`nUsers with Password Not Required:" -Type "Vuln"
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -Properties @(
        "samaccountname", "useraccountcontrol"
    )
    $pwdNotRequired = $searcher.FindAll()
    Write-Result "  Count: $($pwdNotRequired.Count)" -Type "Vuln"
    
    foreach ($user in $pwdNotRequired) {
        $obj = Convert-ADSIResult $user
        $uac = [int]$obj.useraccountcontrol
        $enabled = -not ($uac -band 2)
        if ($enabled) {
            Write-Result "  • [!] $($obj.samaccountname)" -Type "Vuln"
        }
    }
    
    # Reversible Encryption
    Write-Result "`nUsers with Reversible Encryption:" -Type "Vuln"
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))" -Properties @(
        "samaccountname", "useraccountcontrol"
    )
    $reversible = $searcher.FindAll()
    Write-Result "  Count: $($reversible.Count)" -Type "Vuln"
    
    foreach ($user in $reversible) {
        $obj = Convert-ADSIResult $user
        Write-Result "  • [!] $($obj.samaccountname)" -Type "Vuln"
    }
}

function Get-UsersSIDHistory {
    Write-QueryHeader "Users with SID History"
    
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(sidHistory=*))" -Properties @(
        "samaccountname", "sidhistory", "distinguishedname"
    )
    
    $sidHistoryUsers = $searcher.FindAll()
    Write-Result "Users with SID History: $($sidHistoryUsers.Count)" -Type "Warning"
    
    foreach ($user in $sidHistoryUsers) {
        $obj = Convert-ADSIResult $user
        Write-Result "  • $($obj.samaccountname)" -Type "Warning"
        if ($obj.sidhistory) {
            foreach ($sid in $obj.sidhistory) {
                try {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid, 0)
                    Write-Result "    └─ SID History: $($sidObj.Value)" -Type "Info"
                } catch {
                    Write-Result "    └─ SID History: [Binary Data]" -Type "Info"
                }
            }
        }
    }
}

function Get-UsersPasswordInDescription {
    Write-QueryHeader "Users with Password Keywords in Description"
    
    $keywords = @("pass", "pwd", "password", "kenn", "login", "cred")
    $filter = "(&(objectClass=user)(|"
    foreach ($keyword in $keywords) {
        $filter += "(description=*$keyword*)"
    }
    $filter += "))"
    
    $searcher = Get-DomainSearcher -Filter $filter -Properties @(
        "samaccountname", "description", "useraccountcontrol"
    )
    
    $users = $searcher.FindAll()
    Write-Result "Users with password keywords in description: $($users.Count)" -Type "Warning"
    
    foreach ($user in $users) {
        $obj = Convert-ADSIResult $user
        $uac = [int]$obj.useraccountcontrol
        $enabled = -not ($uac -band 2)
        
        if ($enabled) {
            Write-Result "  • $($obj.samaccountname)" -Type "Warning"
            Write-Result "    └─ $($obj.description)" -Type "Info"
        }
    }
}

# ============================================================================
# GROUP ENUMERATION
# ============================================================================

function Get-PrivilegedGroups {
    Write-SectionHeader "3. GROUP ENUMERATION"
    
    Write-QueryHeader "Privileged Groups"
    
    # Well-known privileged groups
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
        $searcher = Get-DomainSearcher -Filter "(&(objectClass=group)(name=$groupName))" -Properties @(
            "samaccountname", "member", "distinguishedname", "description"
        )
        
        $result = $searcher.FindOne()
        if ($result) {
            $obj = Convert-ADSIResult $result
            Write-Result "`n$groupName Members:" -Type "Success"
            
            if ($obj.member) {
                $members = if ($obj.member -is [array]) { $obj.member } else { @($obj.member) }
                Write-Result "  Member Count: $($members.Count)" -Type "Info"
                
                foreach ($memberDN in $members) {
                    # Extract CN from DN
                    if ($memberDN -match "CN=([^,]+)") {
                        Write-Result "  • $($matches[1])" -Type "Info"
                    }
                }
            } else {
                Write-Result "  No members found" -Type "Info"
            }
        }
    }
}

function Get-GroupsWithAdminKeywords {
    Write-QueryHeader "Groups with 'Admin' in Name"
    
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=group)(name=*admin*))" -Properties @(
        "samaccountname", "member", "description"
    )
    
    $adminGroups = $searcher.FindAll()
    Write-Result "Groups containing 'admin': $($adminGroups.Count)" -Type "Info"
    
    foreach ($group in $adminGroups) {
        $obj = Convert-ADSIResult $group
        $memberCount = if ($obj.member) {
            if ($obj.member -is [array]) { $obj.member.Count } else { 1 }
        } else { 0 }
        
        Write-Result "  • $($obj.samaccountname) ($memberCount members)" -Type "Info"
    }
}

function Get-EmptyGroups {
    Write-QueryHeader "Empty Groups"
    
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=group)(!member=*))" -Properties @(
        "samaccountname", "description"
    )
    
    $emptyGroups = $searcher.FindAll()
    Write-Result "Empty Groups: $($emptyGroups.Count)" -Type "Info"
    
    foreach ($group in ($emptyGroups | Select-Object -First 10)) {
        $obj = Convert-ADSIResult $group
        Write-Result "  • $($obj.samaccountname)" -Type "Info"
    }
}

function Get-GroupsWithUsersAndComputers {
    Write-QueryHeader "Groups with Both Users and Computers"
    
    # This is complex without module, we'll identify candidates
    $searcher = Get-DomainSearcher -Filter "(objectClass=group)" -Properties @(
        "samaccountname", "member"
    )
    
    $allGroups = $searcher.FindAll()
    $mixedGroups = @()
    
    foreach ($group in $allGroups) {
        $obj = Convert-ADSIResult $group
        if ($obj.member) {
            $members = if ($obj.member -is [array]) { $obj.member } else { @($obj.member) }
            
            $hasUser = $false
            $hasComputer = $false
            
            foreach ($member in $members) {
                if ($member -match "CN=.*,CN=Computers") { $hasComputer = $true }
                if ($member -match "CN=.*,CN=Users") { $hasUser = $true }
                if ($hasUser -and $hasComputer) { break }
            }
            
            if ($hasUser -and $hasComputer) {
                $mixedGroups += $obj.samaccountname
            }
        }
    }
    
    Write-Result "Groups with both users and computers: $($mixedGroups.Count)" -Type "Warning"
    foreach ($group in $mixedGroups) {
        Write-Result "  • $group" -Type "Info"
    }
}

# ============================================================================
# COMPUTER ENUMERATION
# ============================================================================

function Get-AllComputers {
    Write-SectionHeader "4. COMPUTER ENUMERATION"
    
    Write-QueryHeader "Computer Statistics"
    $searcher = Get-DomainSearcher -Filter "(objectClass=computer)" -Properties @(
        "samaccountname", "dnshostname", "operatingsystem", "operatingsystemversion",
        "useraccountcontrol", "whencreated", "pwdlastset", "serviceprincipalname",
        "lastlogontimestamp", "distinguishedname"
    )
    
    $allComputers = $searcher.FindAll()
    Write-Result "Total Computer Objects: $($allComputers.Count)" -Type "Success"
    
    # Filter enabled computers
    $enabledComputers = $allComputers | Where-Object {
        $uac = [int]$_.Properties.useraccountcontrol[0]
        -not ($uac -band 2)
    }
    Write-Result "Enabled Computers: $($enabledComputers.Count)" -Type "Info"
    
    # Count by OS
    Write-Result "`nOperating System Distribution:" -Type "Info"
    $osGroups = $allComputers | Group-Object { $_.Properties.operatingsystem[0] } | Sort-Object Count -Descending
    
    foreach ($os in $osGroups) {
        $osName = if ($os.Name) { $os.Name } else { "Unknown" }
        Write-Result "  • $osName : $($os.Count)" -Type "Info"
        
        if ($osName -match "2008|2003|Windows 7|XP") {
            Write-Result "    └─ [!] Outdated/Unsupported OS" -Type "Vuln"
        }
    }
}

function Get-DomainControllersDetailed {
    Write-QueryHeader "Domain Controllers (Detailed)"
    
    # Method 1: Primary Group ID 516 (Domain Controllers)
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=computer)(primaryGroupID=516))" -Properties @(
        "samaccountname", "dnshostname", "operatingsystem", "serviceprincipalname"
    )
    
    $dcs = $searcher.FindAll()
    Write-Result "Domain Controllers Found: $($dcs.Count)" -Type "Success"
    
    foreach ($dc in $dcs) {
        $obj = Convert-ADSIResult $dc
        Write-Result "  • $($obj.dnshostname)" -Type "Info"
        Write-Result "    └─ OS: $($obj.operatingsystem)" -Type "Info"
        
        if ($obj.operatingsystem -match "2008|2003") {
            Write-Result "    └─ [!] Outdated OS Version" -Type "Vuln"
        }
    }
}

function Get-ComputersWithoutLAPS {
    Write-QueryHeader "Computers without LAPS"
    
    # Check for ms-Mcs-AdmPwd attribute (LAPS password)
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=computer)(!(primaryGroupID=516)))" -Properties @(
        "samaccountname", "ms-Mcs-AdmPwd", "useraccountcontrol"
    )
    
    $allComputers = $searcher.FindAll()
    $noLAPS = $allComputers | Where-Object {
        $obj = Convert-ADSIResult $_
        $uac = [int]$obj.useraccountcontrol
        $enabled = -not ($uac -band 2)
        $enabled -and (-not $obj.'ms-mcs-admpwd')
    }
    
    Write-Result "Computers without LAPS: $($noLAPS.Count)" -Type "Warning"
    
    foreach ($computer in ($noLAPS | Select-Object -First 10)) {
        $obj = Convert-ADSIResult $computer
        Write-Result "  • $($obj.samaccountname)" -Type "Info"
    }
}

function Get-ComputersWithSPN {
    Write-QueryHeader "Computers with Interesting SPNs"
    
    # SQL Servers
    Write-Result "`nComputers with SQL SPNs:" -Type "Warning"
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=computer)(servicePrincipalName=*SQL*))" -Properties @(
        "samaccountname", "dnshostname", "serviceprincipalname"
    )
    
    $sqlComputers = $searcher.FindAll()
    Write-Result "  Count: $($sqlComputers.Count)" -Type "Info"
    
    foreach ($computer in $sqlComputers) {
        $obj = Convert-ADSIResult $computer
        Write-Result "  • $($obj.dnshostname)" -Type "Info"
    }
}

# ============================================================================
# KERBEROS DELEGATION
# ============================================================================

function Get-UnconstrainedDelegation {
    Write-SectionHeader "5. KERBEROS DELEGATION"
    
    Write-QueryHeader "Unconstrained Delegation"
    
    # TRUSTED_FOR_DELEGATION = 0x80000 (524288)
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" -Properties @(
        "samaccountname", "dnshostname", "useraccountcontrol", "serviceprincipalname"
    )
    
    $unconstrainedComputers = $searcher.FindAll()
    Write-Result "Computers with Unconstrained Delegation (excluding DCs): $($unconstrainedComputers.Count)" -Type "Warning"
    
    foreach ($computer in $unconstrainedComputers) {
        $obj = Convert-ADSIResult $computer
        Write-Result "  • [!] $($obj.dnshostname)" -Type "Vuln"
    }
    
    # Check users too
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -Properties @(
        "samaccountname", "useraccountcontrol"
    )
    
    $unconstrainedUsers = $searcher.FindAll()
    if ($unconstrainedUsers.Count -gt 0) {
        Write-Result "`nUsers with Unconstrained Delegation: $($unconstrainedUsers.Count)" -Type "Warning"
        foreach ($user in $unconstrainedUsers) {
            $obj = Convert-ADSIResult $user
            Write-Result "  • [!] $($obj.samaccountname)" -Type "Vuln"
        }
    }
}

function Get-ConstrainedDelegation {
    Write-QueryHeader "Constrained Delegation"
    
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=*)(msds-allowedtodelegateto=*))" -Properties @(
        "samaccountname", "objectclass", "msds-allowedtodelegateto", "useraccountcontrol"
    )
    
    $constrainedObjects = $searcher.FindAll()
    Write-Result "Objects with Constrained Delegation: $($constrainedObjects.Count)" -Type "Warning"
    
    foreach ($obj in $constrainedObjects) {
        $object = Convert-ADSIResult $obj
        $objectType = if ($object.objectclass -contains "computer") { "Computer" } else { "User" }
        
        Write-Result "  • [$objectType] $($object.samaccountname)" -Type "Warning"
        
        $delegateTo = if ($object.'msds-allowedtodelegateto' -is [array]) {
            $object.'msds-allowedtodelegateto'
        } else {
            @($object.'msds-allowedtodelegateto')
        }
        
        foreach ($target in $delegateTo) {
            Write-Result "    └─ Can delegate to: $target" -Type "Info"
        }
        
        # Check for protocol transition
        $uac = [int]$object.useraccountcontrol
        if ($uac -band 0x1000000) {  # TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
            Write-Result "    └─ [!] Protocol Transition Enabled" -Type "Vuln"
        }
    }
}

function Get-ResourceBasedConstrainedDelegation {
    Write-QueryHeader "Resource-Based Constrained Delegation (RBCD)"
    
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))" -Properties @(
        "samaccountname", "dnshostname", "msDS-AllowedToActOnBehalfOfOtherIdentity"
    )
    
    $rbcdComputers = $searcher.FindAll()
    Write-Result "Computers with RBCD configured: $($rbcdComputers.Count)" -Type "Warning"
    
    foreach ($computer in $rbcdComputers) {
        $obj = Convert-ADSIResult $computer
        Write-Result "  • $($obj.dnshostname)" -Type "Warning"
        Write-Result "    └─ Has msDS-AllowedToActOnBehalfOfOtherIdentity set" -Type "Info"
    }
}

# ============================================================================
# ACL / PERMISSIONS
# ============================================================================

function Get-InterestingACLs {
    Write-SectionHeader "6. ACL & PERMISSIONS"
    
    Write-QueryHeader "Users with Interesting Permissions"
    
    # This is complex without module - we'll check for known dangerous configurations
    Write-Result "Note: Full ACL enumeration requires more complex LDAP queries" -Type "Info"
    Write-Result "Checking for users in privileged groups as proxy..." -Type "Info"
    
    # Check for users in Account Operators
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=group)(name=Account Operators))" -Properties @("member")
    $result = $searcher.FindOne()
    
    if ($result) {
        $obj = Convert-ADSIResult $result
        if ($obj.member) {
            Write-Result "`nAccount Operators Members (can create users):" -Type "Warning"
            $members = if ($obj.member -is [array]) { $obj.member } else { @($obj.member) }
            foreach ($member in $members) {
                if ($member -match "CN=([^,]+)") {
                    Write-Result "  • $($matches[1])" -Type "Info"
                }
            }
        }
    }
}

function Get-ExchangePrivileges {
    Write-QueryHeader "Exchange Privileged Groups"
    
    $exchangeGroups = @(
        "Exchange Windows Permissions",
        "Exchange Trusted Subsystem",
        "Organization Management"
    )
    
    foreach ($groupName in $exchangeGroups) {
        $searcher = Get-DomainSearcher -Filter "(&(objectClass=group)(name=$groupName))" -Properties @(
            "samaccountname", "member"
        )
        
        $result = $searcher.FindOne()
        if ($result) {
            $obj = Convert-ADSIResult $result
            Write-Result "`n$groupName :" -Type "Warning"
            
            if ($obj.member) {
                $members = if ($obj.member -is [array]) { $obj.member } else { @($obj.member) }
                Write-Result "  Members: $($members.Count)" -Type "Info"
                
                foreach ($member in ($members | Select-Object -First 5)) {
                    if ($member -match "CN=([^,]+)") {
                        Write-Result "  • $($matches[1])" -Type "Info"
                    }
                }
            } else {
                Write-Result "  No members" -Type "Info"
            }
        }
    }
}

# ============================================================================
# GPO ENUMERATION
# ============================================================================

function Get-GPOInfo {
    Write-SectionHeader "7. GROUP POLICY OBJECTS"
    
    Write-QueryHeader "GPO Enumeration"
    
    $searcher = Get-DomainSearcher -Filter "(objectClass=groupPolicyContainer)" -Properties @(
        "displayname", "distinguishedname", "gpcfilesyspath", "whencreated", "whenchanged"
    )
    
    $gpos = $searcher.FindAll()
    Write-Result "Total GPOs: $($gpos.Count)" -Type "Success"
    
    # Check for GPOs with interesting keywords
    $keywords = @("password", "admin", "laps", "credential", "firewall", "defender", "applocker")
    
    Write-Result "`nGPOs with Security-Relevant Names:" -Type "Warning"
    foreach ($gpo in $gpos) {
        $obj = Convert-ADSIResult $gpo
        $name = $obj.displayname
        
        foreach ($keyword in $keywords) {
            if ($name -match $keyword) {
                Write-Result "  • $name" -Type "Warning"
                Write-Result "    └─ Keyword: $keyword" -Type "Info"
                break
            }
        }
    }
}

# ============================================================================
# ADCS ENUMERATION
# ============================================================================

function Get-ADCSInfo {
    Write-SectionHeader "8. AD CS (Certificate Services)"
    
    Write-QueryHeader "Enterprise CAs"
    
    # Look for Enterprise CAs
    $searcher = Get-DomainSearcher -Filter "(objectClass=pKIEnrollmentService)" -Properties @(
        "name", "dnshostname", "certificatetemplates", "distinguishedname"
    )
    
    $cas = $searcher.FindAll()
    
    if ($cas.Count -gt 0) {
        Write-Result "Enterprise CAs Found: $($cas.Count)" -Type "Success"
        
        foreach ($ca in $cas) {
            $obj = Convert-ADSIResult $ca
            Write-Result "  • CA: $($obj.name)" -Type "Info"
            Write-Result "    └─ Host: $($obj.dnshostname)" -Type "Info"
            
            if ($obj.certificatetemplates) {
                $templates = if ($obj.certificatetemplates -is [array]) {
                    $obj.certificatetemplates
                } else {
                    @($obj.certificatetemplates)
                }
                Write-Result "    └─ Published Templates: $($templates.Count)" -Type "Info"
            }
        }
    } else {
        Write-Result "No Enterprise CAs found in domain" -Type "Info"
    }
    
    Write-QueryHeader "Certificate Templates"
    
    $templateSearcher = Get-DomainSearcher -Filter "(objectClass=pKICertificateTemplate)" -Properties @(
        "name", "displayname", "pkiextendedkeyusage", "mspki-certificate-name-flag",
        "mspki-enrollment-flag", "distinguishedname"
    )
    
    $templates = $templateSearcher.FindAll()
    
    if ($templates.Count -gt 0) {
        Write-Result "Certificate Templates: $($templates.Count)" -Type "Info"
        
        # Check for potentially vulnerable templates
        foreach ($template in $templates) {
            $obj = Convert-ADSIResult $template
            
            # Check for client authentication EKU
            if ($obj.pkiextendedkeyusage -contains "1.3.6.1.5.5.7.3.2") {
                $nameFlag = [int]$obj.'mspki-certificate-name-flag'
                
                # ENROLLEE_SUPPLIES_SUBJECT = 1
                if ($nameFlag -band 1) {
                    Write-Result "  • [!] $($obj.name) - Allows SAN (potential ESC1)" -Type "Vuln"
                }
            }
        }
    }
}

# ============================================================================
# SPECIAL QUERIES
# ============================================================================

function Get-OwnedObjects {
    Write-SectionHeader "9. OWNED OBJECTS TRACKING"
    
    Write-QueryHeader "Objects Marked as Owned"
    
    # Look for objects with 'owned' in description or custom attributes
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(description=*owned*))" -Properties @(
        "samaccountname", "description"
    )
    
    $ownedUsers = $searcher.FindAll()
    Write-Result "Users with 'owned' in description: $($ownedUsers.Count)" -Type "Info"
    
    foreach ($user in $ownedUsers) {
        $obj = Convert-ADSIResult $user
        Write-Result "  • $($obj.samaccountname)" -Type "Info"
    }
    
    Write-Result "`nNote: For proper 'owned' tracking, use BloodHound CE's tagging feature" -Type "Info"
}

function Get-ForeignSecurityPrincipals {
    Write-QueryHeader "Foreign Security Principals"
    
    $searcher = Get-DomainSearcher -Filter "(objectClass=foreignSecurityPrincipal)" -Properties @(
        "distinguishedname", "objectsid"
    )
    
    $fsps = $searcher.FindAll()
    Write-Result "Foreign Security Principals: $($fsps.Count)" -Type "Warning"
    
    if ($fsps.Count -gt 0) {
        Write-Result "Note: Indicates trust relationships or external domain access" -Type "Info"
        
        foreach ($fsp in ($fsps | Select-Object -First 10)) {
            $obj = Convert-ADSIResult $fsp
            if ($obj.objectsid) {
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($obj.objectsid[0], 0)
                    Write-Result "  • SID: $($sid.Value)" -Type "Info"
                } catch {
                    Write-Result "  • [Binary SID]" -Type "Info"
                }
            }
        }
    }
}

function Get-SensitiveObjects {
    Write-QueryHeader "Sensitive Objects (Cannot be Delegated)"
    
    # SENSITIVE_ACCOUNT = 0x100000 (1048576)
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=1048576))" -Properties @(
        "samaccountname", "memberof"
    )
    
    $sensitiveUsers = $searcher.FindAll()
    Write-Result "Users marked as sensitive: $($sensitiveUsers.Count)" -Type "Info"
    
    foreach ($user in $sensitiveUsers) {
        $obj = Convert-ADSIResult $user
        Write-Result "  • $($obj.samaccountname)" -Type "Info"
    }
}

function Get-ProtectedUsersGroup {
    Write-QueryHeader "Protected Users Group Members"
    
    $searcher = Get-DomainSearcher -Filter "(&(objectClass=group)(name=Protected Users))" -Properties @(
        "member"
    )
    
    $result = $searcher.FindOne()
    
    if ($result) {
        $obj = Convert-ADSIResult $result
        if ($obj.member) {
            $members = if ($obj.member -is [array]) { $obj.member } else { @($obj.member) }
            Write-Result "Protected Users Group Members: $($members.Count)" -Type "Success"
            
            foreach ($member in $members) {
                if ($member -match "CN=([^,]+)") {
                    Write-Result "  • $($matches[1])" -Type "Info"
                }
            }
        } else {
            Write-Result "Protected Users Group is empty" -Type "Warning"
        }
    } else {
        Write-Result "Protected Users Group not found" -Type "Info"
    }
}

# ============================================================================
# CROSS-DOMAIN ATTACKS
# ============================================================================

function Get-CrossDomainObjects {
    Write-SectionHeader "10. CROSS-DOMAIN ENUMERATION"
    
    Write-QueryHeader "Users with Cross-Domain Group Membership"
    
    try {
        $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $currentDomainName = $currentDomain.Name
        
        $searcher = Get-DomainSearcher -Filter "(objectClass=user)" -Properties @(
            "samaccountname", "memberof"
        )
        
        $allUsers = $searcher.FindAll()
        $crossDomainUsers = @()
        
        foreach ($user in $allUsers) {
            $obj = Convert-ADSIResult $user
            if ($obj.memberof) {
                $groups = if ($obj.memberof -is [array]) { $obj.memberof } else { @($obj.memberof) }
                
                foreach ($group in $groups) {
                    if ($group -notmatch "DC=$($currentDomainName.Replace('.',',DC='))") {
                        $crossDomainUsers += $obj.samaccountname
                        break
                    }
                }
            }
        }
        
        Write-Result "Users with foreign domain group membership: $($crossDomainUsers.Count)" -Type "Warning"
        
        foreach ($user in ($crossDomainUsers | Select-Object -First 10)) {
            Write-Result "  • $user" -Type "Info"
        }
        
    } catch {
        Write-Result "Error checking cross-domain memberships: $_" -Type "Warning"
    }
}

# ============================================================================
# BLOODHOUND EXPORT EQUIVALENT
# ============================================================================

function Export-BloodHoundData {
    Write-SectionHeader "11. EXPORT BLOODHOUND-STYLE DATA"
    
    if ($ExportCSV) {
        if (!(Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        Write-QueryHeader "Exporting enumeration data to CSV..."
        
        # Export Users
        $searcher = Get-DomainSearcher -Filter "(objectClass=user)" -Properties @(
            "samaccountname", "distinguishedname", "admincount", "serviceprincipalname",
            "useraccountcontrol", "pwdlastset", "lastlogontimestamp", "memberof"
        )
        $users = $searcher.FindAll() | ForEach-Object { Convert-ADSIResult $_ }
        $users | Export-Csv -Path "$OutputPath\users.csv" -NoTypeInformation
        Write-Result "Exported: users.csv" -Type "Success"
        
        # Export Computers
        $searcher = Get-DomainSearcher -Filter "(objectClass=computer)" -Properties @(
            "samaccountname", "dnshostname", "operatingsystem", "useraccountcontrol",
            "serviceprincipalname", "pwdlastset"
        )
        $computers = $searcher.FindAll() | ForEach-Object { Convert-ADSIResult $_ }
        $computers | Export-Csv -Path "$OutputPath\computers.csv" -NoTypeInformation
        Write-Result "Exported: computers.csv" -Type "Success"
        
        # Export Groups
        $searcher = Get-DomainSearcher -Filter "(objectClass=group)" -Properties @(
            "samaccountname", "distinguishedname", "member", "memberof"
        )
        $groups = $searcher.FindAll() | ForEach-Object { Convert-ADSIResult $_ }
        $groups | Export-Csv -Path "$OutputPath\groups.csv" -NoTypeInformation
        Write-Result "Exported: groups.csv" -Type "Success"
        
        Write-Result "`nAll data exported to: $OutputPath" -Type "Success"
    } else {
        Write-Result "Use -ExportCSV switch to export data" -Type "Info"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-BloodHoundEnumeration {
    Write-Banner
    
    Write-Host "[*] Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[*] Running as: $env:USERDOMAIN\$env:USERNAME`n" -ForegroundColor Gray
    
    # Test domain connectivity
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        Write-Host "[✓] Connected to domain: $($domain.Name)`n" -ForegroundColor Green
    } catch {
        Write-Host "[!] ERROR: Cannot connect to AD domain" -ForegroundColor Red
        Write-Host "[!] Error: $_" -ForegroundColor Red
        return
    }
    
    # Run all enumeration modules
    try {
        Get-DomainInfo
        Get-AllUsers
        Get-PrivilegedUsers
        Get-KerberoastableUsers
        Get-ASREPRoastableUsers
        Get-PasswordIssues
        Get-UsersSIDHistory
        Get-UsersPasswordInDescription
        Get-PrivilegedGroups
        Get-GroupsWithAdminKeywords
        Get-EmptyGroups
        Get-GroupsWithUsersAndComputers
        Get-AllComputers
        Get-DomainControllersDetailed
        Get-ComputersWithoutLAPS
        Get-ComputersWithSPN
        Get-UnconstrainedDelegation
        Get-ConstrainedDelegation
        Get-ResourceBasedConstrainedDelegation
        Get-InterestingACLs
        Get-ExchangePrivileges
        Get-GPOInfo
        Get-ADCSInfo
        Get-OwnedObjects
        Get-ForeignSecurityPrincipals
        Get-SensitiveObjects
        Get-ProtectedUsersGroup
        Get-CrossDomainObjects
        Export-BloodHoundData
        
    } catch {
        Write-Host "`n[!] Error during enumeration: $_" -ForegroundColor Red
    }
    
    Write-Host "`n" -NoNewline
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                    ENUMERATION COMPLETE                     ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "`n[*] Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[*] Review findings marked with [!] for potential security issues" -ForegroundColor Yellow
}

# Execute main function
Start-BloodHoundEnumeration
