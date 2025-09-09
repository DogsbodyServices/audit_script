# ACTT Windows Script – Multi‑Tenant Risk Annotations

> Generated automatically. Each finding includes line number(s), context, risk, and a concrete remediation.

**Source file:** `ACTT_WINDOWS_Script.ps1`  
**Total findings:** 79

## Table of Contents

- [DirectorySearcher usage](#directorysearcher-usage)  

- [Querying cn=Partitions (configuration NC)](#querying-cn-partitions-configuration-nc)  

- [Adding domain DN as OU root](#adding-domain-dn-as-ou-root)  

- [Get-ADOrganizationalUnit -Filter * without -SearchBase](#get-adorganizationalunit-filter-without-searchbase)  

- [OU list built from all OUs](#ou-list-built-from-all-ous)  

- [Sensitive export file](#sensitive-export-file)  

- [Enumerating ACLs over all OUs](#enumerating-acls-over-all-ous)  

- [Enumerating all domain controllers](#enumerating-all-domain-controllers)  

- [GPO report generation (likely domain-wide)](#gpo-report-generation-likely-domain-wide)  

- [Trusts enumeration](#trusts-enumeration)  

- [Get-ADGroup -Filter * without -SearchBase](#get-adgroup-filter-without-searchbase)  

- [Get-ADUser -Filter * without -SearchBase](#get-aduser-filter-without-searchbase)  

- [DirectorySearcher with empty ADSI root (default naming context)](#directorysearcher-with-empty-adsi-root-default-naming-context)  

- [DirectorySearcher user filter without constrained SearchRoot](#directorysearcher-user-filter-without-constrained-searchroot)  

- [Domain password policy extraction](#domain-password-policy-extraction)  

- [Fine-grained password settings (PSO) enumeration](#fine-grained-password-settings-pso-enumeration)  


## DirectorySearcher usage

**Risk:** Potential domain-wide enumeration if SearchRoot is not set to a constrained base DN.

**Recommended fix:** After creating DirectorySearcher, set .SearchRoot to the customer's OU DN and avoid querying cn=Partitions unless required.

**Occurrences:**

- **Line 638** (pattern `new-?object\s+System\.DirectoryServices\.DirectorySearcher`):

```powershell
   634: 		function Get-NETBiosName ( $dn, $ConfigurationNC ) 
   635: 		{ 
   636: 			try 
   637: 			{ 
   638: 				$Searcher = New-Object System.DirectoryServices.DirectorySearcher  
   639: 				$Searcher.SearchScope = "subtree"  
   640: 				$Searcher.PropertiesToLoad.Add("nETBIOSName")| Out-Null 
   641: 				$Searcher.SearchRoot = "LDAP://cn=Partitions,$ConfigurationNC" 
   642: 				$Searcher.Filter = "(nCName=$dn)" 
```

- **Line 1923** (pattern `new-?object\s+System\.DirectoryServices\.DirectorySearcher`):

```powershell
  1919: 		Write-ACTTDataLog -Message 'List all Domain Users Accounts - users.actt via DirectorySearcher'
  1920: 		Write-host 'List all Domain Users Accounts- users.actt'
  1921: 				
  1922: 		$root = [ADSI]''
  1923:         $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
  1924: 
  1925: 		$searcher.filter = "(&(objectCategory=person)(objectClass=user))"
  1926: 		
  1927: 		$searcher.PropertiesToLoad.AddRange(@("SamAccountName","DistinguishedName","ObjectSID","Name","Description","pwdlastset","useraccountcontrol", "whencreated", "lastlogontimestamp", "whenchanged", "accountexpires"))
```

- **Line 2052** (pattern `new-?object\s+System\.DirectoryServices\.DirectorySearcher`):

```powershell
  2048: 		Write-ACTTDataLog -Message 'List all Domain PSOs Accounts - PSOs.actt via DirectorySearcher'
  2049: 		Write-host 'List all Domain PSOs Accounts- PSOs.actt'
  2050: 				
  2051: 		$root = [ADSI]''
  2052:         $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
  2053: 
  2054: 		$searcher.filter = "(objectClass=msDS-PasswordSettings)"
  2055: 		
  2056: 		$searcher.PropertiesToLoad.AddRange(@("msds-lockoutduration","msds-minimumpasswordage","msds-lockoutobservationwindow","msds-maximumpasswordage","msds-lockoutthreshold","msds-passwordcomplexityenabled","msds-passwordhistorylength", "msds-minimumpasswordlength", "msds-psoappliesto", "whenchanged", "msds-passwordsettingsprecedence","cn"))
```

_Tags: review, scope_


## Querying cn=Partitions (configuration NC)

**Risk:** Reads forest-wide partition data; not tenant-scoped and reveals global directory structure.

**Recommended fix:** Avoid cn=Partitions in multi-tenant contexts. If NetBIOS is needed, inject it as a parameter or resolve within allowed scope.

**Occurrences:**

- **Line 641** (pattern `SearchRoot\s*=\s*\"LDAP://cn=Partitions`):

```powershell
   637: 			{ 
   638: 				$Searcher = New-Object System.DirectoryServices.DirectorySearcher  
   639: 				$Searcher.SearchScope = "subtree"  
   640: 				$Searcher.PropertiesToLoad.Add("nETBIOSName")| Out-Null 
   641: 				$Searcher.SearchRoot = "LDAP://cn=Partitions,$ConfigurationNC" 
   642: 				$Searcher.Filter = "(nCName=$dn)" 
   643: 				$NetBIOSName = ($Searcher.FindOne()).Properties.Item("nETBIOSName") 
   644: 				Return $NetBIOSName 
   645: 			} 
```

_Tags: forest, privacy_


## Adding domain DN as OU root

**Risk:** Seeds OU iteration with the domain root, guaranteeing traversal outside the tenant's OU.

**Recommended fix:** Start from the customer's OU DN(s) only.

**Occurrences:**

- **Line 739** (pattern `\$OUs\s*=\s*@\(\s*Get-ADDomain\s*\|\s*Select-Object\s*-ExpandProperty\s+DistinguishedName`):

```powershell
   735: 
   736: 
   737: # Get a list of all OUs.  Add in the root containers for good measure (users, computers, etc.).
   738: 
   739: $OUs  = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
   740: $OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
   741: [String]$DomainDN = ''
   742: #$ForestFQDN.split('.') | %{ $DomainDN="DN=$($_),$DomainDN"}
   743: $DomainDN = "DC="+ $ForestFQDN.Replace('.',',DC=')
```

_Tags: OU, scope_


## Get-ADOrganizationalUnit -Filter * without -SearchBase

**Risk:** Enumerates all OUs in the domain, exposing other tenants' structure.

**Recommended fix:** Add -SearchBase 'OU=CustomerX,DC=shared,DC=local' and consider -SearchScope Subtree.

**Occurrences:**

- **Line 740** (pattern `\bGet-ADOrganizationalUnit\b.*-Filter\s+\*`):

```powershell
   736: 
   737: # Get a list of all OUs.  Add in the root containers for good measure (users, computers, etc.).
   738: 
   739: $OUs  = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
   740: $OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
   741: [String]$DomainDN = ''
   742: #$ForestFQDN.split('.') | %{ $DomainDN="DN=$($_),$DomainDN"}
   743: $DomainDN = "DC="+ $ForestFQDN.Replace('.',',DC=')
   744: $OUs += Get-ADObject -Server $ComputerName -SearchBase $DomainDN -SearchScope OneLevel -LDAPFilter '(objectClass=container)'| Select-Object -ExpandProperty DistinguishedName
```

- **Line 1410** (pattern `\bGet-ADOrganizationalUnit\b.*-Filter\s+\*`):

```powershell
  1406: 		Report Fields: 'Name', 'objectClass', 'Description', 'WhenCreated', 'LinkedGroupPolicyObjects', 'DistinguishedName'
  1407: 		Pass in Domain, Domain Controller, File, Report Fields
  1408: 		#>
  1409: 		Write-Host 'Searching All OUs'
  1410: 		$AllOUs = Get-ADOrganizationalUnit -Server $Server -Filter * -Properties Name, objectClass, Description, WhenCreated, LinkedGroupPolicyObjects, DistinguishedName -ErrorAction Stop
  1411: 		
  1412: 		$colOUs = @()
  1413: 		
  1414: 		foreach ($OU in $AllOUs)
```

_Tags: OU, domain-wide, privacy_


## OU list built from all OUs

**Risk:** Populates the OU list with every OU in the domain for later ACL dumps.

**Recommended fix:** Replace with an explicit list of the customer's OU DN(s).

**Occurrences:**

- **Line 740** (pattern `\$OUs\s*\+\=\s*Get-ADOrganizationalUnit\s*-Filter\s*\*`):

```powershell
   736: 
   737: # Get a list of all OUs.  Add in the root containers for good measure (users, computers, etc.).
   738: 
   739: $OUs  = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
   740: $OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
   741: [String]$DomainDN = ''
   742: #$ForestFQDN.split('.') | %{ $DomainDN="DN=$($_),$DomainDN"}
   743: $DomainDN = "DC="+ $ForestFQDN.Replace('.',',DC=')
   744: $OUs += Get-ADObject -Server $ComputerName -SearchBase $DomainDN -SearchScope OneLevel -LDAPFilter '(objectClass=container)'| Select-Object -ExpandProperty DistinguishedName
```

_Tags: OU, privacy_


## Sensitive export file

**Risk:** This export likely contains data beyond a single tenant if not scoped.

**Recommended fix:** Ensure each producer function is OU-scoped or removed.

**Occurrences:**

- **Line 750** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
   746: #$excludedObjectGuids = $excludedIdentities | ForEach-Object { $schemaIDGUID | Where-Object { $_.Value -eq $_ } | Select-Object -Property Key }
   747: # $lapsAttrGuid = $schemaIDGUID.GetEnumerator() | Where-Object { $_.Value -eq 'ms-Mcs-AdmPwd' }
   748: 
   749: 
   750: $Path = Join-Path $Path 'OUPermissions.actt'
   751: $Header = "[AccessControlType] NVARCHAR(MAX)|^|[ActiveDirectoryRights] NVARCHAR(MAX)|^|[identityName] NVARCHAR(MAX)|^|[IdentityReference] NVARCHAR(MAX)|^|[InheritanceFlags] NVARCHAR(MAX)|^|[InheritanceType] NVARCHAR(MAX)|^|[inheritedObjectTypeName] NVARCHAR(MAX)|^|[IsInherited] NVARCHAR(MAX)|^|[objectTypeName] NVARCHAR(MAX)|^|[organizationalUnit] NVARCHAR(MAX)|^|[organizationalUnitCN] NVARCHAR(MAX)|^|[PropagationFlags] NVARCHAR(MAX)"
   752: $swriter = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::Unicode)
   753: $swriter.WriteLine($Header)
   754: $swriter.Close()
```

- **Line 813** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
   809:         [void]$stb.Append($Properties.organizationalUnit).Append('|^|')
   810:         [void]$stb.Append($Properties.organizationalUnitCN).Append('|^|')
   811:         [void]$stb.Append($Properties.PropagationFlags).AppendLine()
   812:       }
   813:        # $stb.ToString() | Out-File -Append -FilePath $(Join-Path $Path 'OUPermissions.actt')
   814:         $swriter = New-Object System.IO.StreamWriter($Path, $true, [System.Text.Encoding]::Unicode)
   815:         $swriter.WriteLine($stb.ToString().Trim())
   816:         $swriter.Close()
   817:         [void]$stb.Clear()
```

- **Line 869** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
   865: 		
   866: 		
   867: 		Write-ACTTDataLog -Message 'Exporting Domain Controllers - DomainControllers.actt'
   868: 		Write-host 'Exporting Domain Controllers - DomainControllers.actt'
   869: 		Write-ActtFile -Data $colDomainControllers -Path $(Join-Path $Path 'DomainControllers.actt')
   870: 		
   871: 	}
   872: 	catch
   873: 	{
```

- **Line 1214** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1210: 		}
  1211: 		
  1212: 		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
  1213: 		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
  1214: 		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
  1215: 	}
  1216: 	
  1217: 	Catch
  1218: 	{
```

- **Line 1268** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1264: 		}
  1265: 		
  1266: 		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
  1267: 		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
  1268: 		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
  1269: 	}
  1270: 	
  1271: 	Catch
  1272: 	{
```

- **Line 1525** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1521: 		}
  1522: 		
  1523: 		Write-ACTTDataLog -Message 'Exporting All Domain Groups - groups.actt'
  1524: 		Write-host 'Exporting All Domain Groups - groups.actt'
  1525: 		Write-ActtFile -Data $colGroups -Path $(Join-Path $Path 'groups.actt')
  1526: 	}
  1527: 	
  1528: 	Catch
  1529: 	{
```

- **Line 1548** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1544: 				   Mandatory = $true)]
  1545: 		[Object]$Path)
  1546:     #List all members in Domain Groups - groupmembers.actt
  1547: 	Try{
  1548:             $Path = Join-Path $Path 'groupmembers.actt'
  1549: 			Write-ACTTDataLog -Message 'List all Domain Group Members - groupmembers.actt'
  1550: 		<#
  1551: 			File: groupmembers.actt
  1552: 			Report Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'
```

- **Line 1736** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1732: 		}
  1733: 		
  1734: 		Write-ACTTDataLog -Message 'Exporting Sensitive Domain Group Members - groupmembers2.actt'
  1735: 		Write-host 'Exporting Sensitive Domain Group Members - groupmembers2.actt'
  1736: 		Write-ActtFile -Data $colSensitiveDomainGroups -Path $(Join-Path $Path 'groupmembers2.actt')
  1737: 	}
  1738: 	
  1739: 	Catch
  1740: 	{
```

- **Line 1823** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1819: 		}
  1820: 		
  1821: 		Write-host 'Exporting All Domain Users - users.actt'
  1822: 		Write-ACTTDataLog -Message 'Exporting All Domain Users - users.actt'
  1823: 		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt')
  1824: 		
  1825: 		Write-host 'Exporting All Domain Users - users2.actt'
  1826: 		Write-ACTTDataLog -Message 'Exporting All Domain Users - users2.actt'
  1827: 		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users2.actt')
```

- **Line 1827** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1823: 		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt')
  1824: 		
  1825: 		Write-host 'Exporting All Domain Users - users2.actt'
  1826: 		Write-ACTTDataLog -Message 'Exporting All Domain Users - users2.actt'
  1827: 		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users2.actt')
  1828: 	}
  1829: 	
  1830: 	Catch
  1831: 	{
```

- **Line 1894** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1890: 		
  1891: 				
  1892: 		Write-host 'Exporting All Domain Users - users2.actt'
  1893: 		Write-ACTTDataLog -Message 'Exporting All Domain Users - users2.actt'
  1894: 		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users2.actt')
  1895: 	}
  1896: 	
  1897: 	Catch
  1898: 	{
```

- **Line 1959** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  1955: 						
  1956:       }			
  1957: 				
  1958: 		Write-host 'Exporting All Domain Users - users.actt'
  1959: 		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt')
  1960: 		Write-ACTTDataLog -Message 'Exporting All Domain Users - users.actt'
  1961: 				
  1962: 	}
  1963: 	
```

- **Line 2480** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  2476: 		}
  2477: 		
  2478: 		Write-ACTTDataLog -Message 'Exporting All Local Groups - groups.actt'
  2479: 		Write-host 'Exporting All Local Groups - groups.actt'
  2480: 		Write-ActtFile -Data $colGroups -Path $(Join-Path $Path 'groups.actt')
  2481: 	}
  2482: 	
  2483: 	Catch
  2484: 	{
```

- **Line 2582** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  2578: 		
  2579: 		
  2580: 		Write-ACTTDataLog -Message 'Exporting All Local Groupmembers - groupmembers.actt'
  2581: 		Write-host 'Exporting All Local Group members - groupmembers.actt'
  2582: 		Write-ActtFile -Data $colLocalGroupsMembers -Path $(Join-Path $Path 'groupmembers.actt')
  2583: 	}
  2584: 	
  2585: 	Catch
  2586: 	{
```

- **Line 2852** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  2848: 		}
  2849: 		
  2850: 		
  2851: 		Write-ACTTDataLog -Message 'Exporting All Local Users - users.actt'
  2852: 		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt')
  2853: 		Write-host 'Exporting All Local Users - users.actt'
  2854: 		
  2855: 		Write-ACTTDataLog -Message 'Exporting All Local Users - users3.actt'
  2856: 		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users3.actt')
```

- **Line 2856** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  2852: 		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt')
  2853: 		Write-host 'Exporting All Local Users - users.actt'
  2854: 		
  2855: 		Write-ACTTDataLog -Message 'Exporting All Local Users - users3.actt'
  2856: 		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users3.actt')
  2857: 		Write-host 'Exporting All Local Users - users3.actt'
  2858: 	}
  2859: 	
  2860: 	Catch
```

- **Line 2938** (pattern `Join-Path\s+\$Path\s+'(users|groups|groupmembers|OUPermissions|GPO|trusts|DomainControllers)[^']*\.actt'`):

```powershell
  2934: 		}
  2935: 		
  2936: 		
  2937: 		Write-ACTTDataLog -Message 'Exporting All Local Users - users2.actt'
  2938: 		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users2.actt')
  2939: 		Write-host 'Exporting All Local Users - users2.actt'
  2940: 	}
  2941: 	
  2942: 	Catch
```

_Tags: export, privacy_


## Enumerating ACLs over all OUs

**Risk:** If $OUs includes the entire domain, this dumps permissions for other tenants' OUs.

**Recommended fix:** Constrain $OUs to only the customer's OU DN(s) before iterating.

**Occurrences:**

- **Line 779** (pattern `Get-ACL\s+-Path\s+\"AD:\\\$OU\"`):

```powershell
   775:     $i++
   776:     Write-Progress -Activity "Exporting OU Permissions" -Status "($i of $total)" -CurrentOperation "Exporting $OU" -PercentComplete ($i/$total*100) -SecondsRemaining $secRemaining
   777:    
   778:     $canonicalName = @{label='organizationalUnitCN';expression={(Format-DistinguishedName -Path $OU)}}
   779:     $ACLs = Get-ACL -Path "AD:\$OU" | Select-Object -ExpandProperty Access | Where({
   780:                            ($_.ActiveDirectoryRights -notin $excludedAccessRights -or $_.objectType.ToString() -eq $lapsAttrGuid) -and ( $_.IdentityReference -notlike 'NT AUTHORITY\*' -and $_.IdentityReference -notlike 'BUILTIN\*' -and $_.identityReference -notlike 'S-1-*' )})|
   781:                            Select-Object $canonicalName,
   782:                            @{name='organizationalUnit';expression={$OU}}, `
   783: 						   IdentityReference,
```

_Tags: ACL, privacy_


## Enumerating all domain controllers

**Risk:** Reveals infrastructure outside the tenant's OU; not OU-scopable.

**Recommended fix:** Remove in shared domains. If strictly required, get only DCs that host the OU's naming context (rare) with owner approval.

**Occurrences:**

- **Line 852** (pattern `\bGet-ADDomainController\b.*-Filter\s+\*`):

```powershell
   848: 	Try
   849: 	{
   850: 		Write-ACTTDataLog -Message 'Get Domains Controllers in the Domain - DomainControllers.actt'
   851: 		Write-Host 'Searching Domain Controllers'
   852: 		$AllDomainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
   853: 		$colDomainControllers = @()
   854: 		
   855: 		
   856: 		ForEach ($attr in $AllDomainControllers)
```

_Tags: infra, non-scopable_


## GPO report generation (likely domain-wide)

**Risk:** By default, queries all GPOs; linked scope may include other tenants' policy objects.

**Recommended fix:** Enumerate only GPOs linked to the customer's OU via Get-GPInheritance on the OU DN, then report those.

**Occurrences:**

- **Line 881** (pattern `Get-GPOReport`):

```powershell
   877: 	
   878: }
   879: 
   880: 
   881: Function Get-GPOReportall
   882: {
   883: 	
   884: 	
   885: 	[CmdletBinding()]
```

- **Line 899** (pattern `Get-GPOReport`):

```powershell
   895: 	Try
   896: 	{
   897: 		Write-ACTTDataLog -Message 'Get All Domain Group Policy Objects Settings GPOReportAll.html'
   898: 		
   899: 		Get-GPOReport -All -ReportType html -Path $(Join-Path $Path 'GPOReportAll.html.txt') -Server $Server 
   900: 				
   901: 		Write-ACTTDataLog -Message 'Exporting All Domain GPOs - GPOReportAll.html'
   902: 		Write-host 'Exporting All Domain GPOs - GPOReportAll.html'
   903: 		
```

- **Line 3211** (pattern `Get-GPOReport`):

```powershell
  3207: 	Get-DefDomainPwdPol -Server $ComputerName -Path $Path
  3208: 	Get-DomainSecPol -Server $ComputerName -Path $Path
  3209: 	Get-FineGrainedPSO -Path $Path
  3210: 	Get-DomainSecPolBoolean -Server $DomainBind -Path $Path
  3211: 	Get-GPOReportall -Server $ComputerName -Path $Path
  3212: 	Get-ServerUserRights -Server $ComputerName -Path $Path
  3213: 	Get-DomainGroupsMembersAll -Server $DomainBind -Path $Path
  3214: 	Get-ServerAuditPolicy -Server $ComputerName -Path $Path
  3215: 	Get-OUPermissions -Domain $DomainBind -Path $Path
```

_Tags: GPO, privacy_


## Trusts enumeration

**Risk:** Exposes inter-domain/forest trust topology; cross-tenant and non-scopable.

**Recommended fix:** Remove in shared domains unless the environment owner authorises it explicitly.

**Occurrences:**

- **Line 1139** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1135: Function Get-DomainTrustsAll
  1136: {
  1137: 	<#
  1138: 	.SYNOPSIS
  1139: 		List Domain Trusts and their status - trusts.actt
  1140: 	
  1141: 	.DESCRIPTION
  1142: 		File: trusts.actt
  1143:         NameSpace: '\root\MicrosoftActiveDirectory'
```

- **Line 1142** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1138: 	.SYNOPSIS
  1139: 		List Domain Trusts and their status - trusts.actt
  1140: 	
  1141: 	.DESCRIPTION
  1142: 		File: trusts.actt
  1143:         NameSpace: '\root\MicrosoftActiveDirectory'
  1144:         Query: 'SELECT * FROM Microsoft_DomainTrustStatus'
  1145:         Report Fields: 'TrustedDomain', 'TrustDirection', 'TrustType', 'TrustAttributes', 'TrustedDCName', 'TrustStatus', 'TrustIsOK'
  1146: 
```

- **Line 1163** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1159: 	.INPUTS
  1160: 		
  1161: 
  1162: 	.OUTPUTS
  1163: 		trusts.actt
  1164: 
  1165: 	.NOTES
  1166: 		
  1167: 
```

- **Line 1186** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1182: 		[Object]$Path)
  1183: 	
  1184: 	Try
  1185: 	{
  1186: 		Write-ACTTDataLog -Message 'List Domain Trusts and their status - trusts.actt'
  1187: 		
  1188: 		$colTrusts = @()
  1189: 		$ADDomainTrusts = Get-ADObject -Server $Server -Filter { ObjectClass -eq 'trustedDomain' } -Properties *
  1190: 		
```

- **Line 1212** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1208: 				$colTrusts += $objStatus
  1209: 			}
  1210: 		}
  1211: 		
  1212: 		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
  1213: 		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
  1214: 		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
  1215: 	}
  1216: 	
```

- **Line 1213** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1209: 			}
  1210: 		}
  1211: 		
  1212: 		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
  1213: 		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
  1214: 		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
  1215: 	}
  1216: 	
  1217: 	Catch
```

- **Line 1214** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1210: 		}
  1211: 		
  1212: 		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
  1213: 		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
  1214: 		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
  1215: 	}
  1216: 	
  1217: 	Catch
  1218: 	{
```

- **Line 1240** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1236: 		[Object]$Path)
  1237: 	
  1238: 	Try
  1239: 	{
  1240: 		Write-ACTTDataLog -Message 'List Domain Trusts and their status - trusts.actt'
  1241: 		
  1242: 		$colTrusts = @()
  1243: 		$ADDomainTrusts = Get-ADTrust -Server $Server -Filter *
  1244: 				
```

- **Line 1243** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1239: 	{
  1240: 		Write-ACTTDataLog -Message 'List Domain Trusts and their status - trusts.actt'
  1241: 		
  1242: 		$colTrusts = @()
  1243: 		$ADDomainTrusts = Get-ADTrust -Server $Server -Filter *
  1244: 				
  1245: 		ForEach ($Trust in $ADDomainTrusts)
  1246: 		{
  1247: 			# WMI Request using the trustmon WMI provider
```

- **Line 1266** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1262: 				$colTrusts += $objStatus
  1263: 			
  1264: 		}
  1265: 		
  1266: 		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
  1267: 		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
  1268: 		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
  1269: 	}
  1270: 	
```

- **Line 1267** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1263: 			
  1264: 		}
  1265: 		
  1266: 		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
  1267: 		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
  1268: 		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
  1269: 	}
  1270: 	
  1271: 	Catch
```

- **Line 1268** (pattern `trusts\.actt|\bGet-ADTrust\b`):

```powershell
  1264: 		}
  1265: 		
  1266: 		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
  1267: 		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
  1268: 		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
  1269: 	}
  1270: 	
  1271: 	Catch
  1272: 	{
```

_Tags: infra, non-scopable, privacy_


## Get-ADGroup -Filter * without -SearchBase

**Risk:** Enumerates all groups in the domain, including other customers'.

**Recommended fix:** Add -SearchBase and, if possible, filter by distinguishedName or canonicalName under the customer's OU.

**Occurrences:**

- **Line 1498** (pattern `\bGet-ADGroup\b.*-Filter\s+\*`):

```powershell
  1494:         File: groups.actt
  1495:         Report Fields: 'GroupName', 'GroupSID', 'Description'
  1496:     #>
  1497: 		Write-Host 'Searching All Domain Groups'
  1498: 		$AllDomainGroups = Get-ADGroup -Server $Server -Filter * -Properties SamAccountName, ObjectSID, Description -ErrorAction Stop
  1499: 		$colGroups = @()
  1500: 		
  1501: 		foreach ($DGroup in $AllDomainGroups)
  1502: 		{
```

- **Line 1555** (pattern `\bGet-ADGroup\b.*-Filter\s+\*`):

```powershell
  1551: 			File: groupmembers.actt
  1552: 			Report Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'
  1553: 		#>
  1554:             Write-Host 'Searching All Domain Group Members'
  1555:             $AllDomainGroups = Get-ADGroup -Server $Server -Filter * -Properties SamAccountName, ObjectSID ,members -ErrorAction Stop
  1556: 			$Header = "[GroupName] NVARCHAR(MAX)|^|[GroupSID] NVARCHAR(MAX)|^|[Member] NVARCHAR(MAX)|^|[objectSID] NVARCHAR(MAX)"
  1557:             $SW = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::Unicode)
  1558:             $SW.WriteLine($Header)
  1559:             $SW.Close()
```

_Tags: domain-wide, groups_


## Get-ADUser -Filter * without -SearchBase

**Risk:** Enumerates all users in the domain.

**Recommended fix:** Add -SearchBase and limit returned properties; or use DirectorySearcher bound to the OU.

**Occurrences:**

- **Line 1773** (pattern `\bGet-ADUser\b.*-Filter\s+\*`):

```powershell
  1769: 			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'
  1770: 			'CannotChangePassword', 'LockedOut', 'Enabled',
  1771: 			'PasswordNeverExpires', 'PasswordNotRequired', 'AccountExpirationDate', 'LastLogonDate', 'whenchanged')
  1772: 		
  1773: 		$AllDomainUsers = Get-ADUser -Server $Server -Filter * -Properties $UserProps
  1774: 		Write-ACTTDataLog -Message "Search Returned $($AllDomainUsers.Count) Users"
  1775: 		Write-Host "Search Returned $($AllDomainUsers.Count) Users"
  1776: 		$colUsers = @()
  1777: 		$colUsers2 = @()
```

- **Line 1863** (pattern `\bGet-ADUser\b.*-Filter\s+\*`):

```powershell
  1859: 			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'
  1860: 			'CannotChangePassword', 'LockedOut', 'Enabled',
  1861: 			'PasswordNeverExpires', 'PasswordNotRequired')
  1862: 		
  1863: 		$AllDomainUsers = Get-ADUser -Server $Server -Filter * -Properties $UserProps
  1864: 		Write-ACTTDataLog -Message "Search Returned $($AllDomainUsers.Count) Users2"
  1865: 		Write-Host "Search Returned $($AllDomainUsers.Count) Users2"
  1866: 		
  1867: 		$colUsers2 = @()
```

_Tags: domain-wide, users_


## DirectorySearcher with empty ADSI root (default naming context)

**Risk:** Binds to the domain's default naming context, making subsequent searches domain-wide in a shared tenant.

**Recommended fix:** Explicitly set SearchRoot to the customer's OU DN (e.g., LDAP://OU=CustomerX,DC=shared,DC=local) and keep SearchScope=Subtree.

**Occurrences:**

- **Line 1922** (pattern `\[ADSI\]''`):

```powershell
  1918: 	{
  1919: 		Write-ACTTDataLog -Message 'List all Domain Users Accounts - users.actt via DirectorySearcher'
  1920: 		Write-host 'List all Domain Users Accounts- users.actt'
  1921: 				
  1922: 		$root = [ADSI]''
  1923:         $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
  1924: 
  1925: 		$searcher.filter = "(&(objectCategory=person)(objectClass=user))"
  1926: 		
```

- **Line 2051** (pattern `\[ADSI\]''`):

```powershell
  2047: 	{
  2048: 		Write-ACTTDataLog -Message 'List all Domain PSOs Accounts - PSOs.actt via DirectorySearcher'
  2049: 		Write-host 'List all Domain PSOs Accounts- PSOs.actt'
  2050: 				
  2051: 		$root = [ADSI]''
  2052:         $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
  2053: 
  2054: 		$searcher.filter = "(objectClass=msDS-PasswordSettings)"
  2055: 		
```

_Tags: domain-wide, privacy, scope_


## DirectorySearcher user filter without constrained SearchRoot

**Risk:** User search filter typically paired with default SearchRoot → domain-wide enumeration.

**Recommended fix:** Set $searcher.SearchRoot to the customer's OU DN before assigning this filter.

**Occurrences:**

- **Line 1925** (pattern `\(objectCategory=person\)\(objectClass=user\)`):

```powershell
  1921: 				
  1922: 		$root = [ADSI]''
  1923:         $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
  1924: 
  1925: 		$searcher.filter = "(&(objectCategory=person)(objectClass=user))"
  1926: 		
  1927: 		$searcher.PropertiesToLoad.AddRange(@("SamAccountName","DistinguishedName","ObjectSID","Name","Description","pwdlastset","useraccountcontrol", "whencreated", "lastlogontimestamp", "whenchanged", "accountexpires"))
  1928: 		$searcher.PageSize = 1000
  1929: 		$USERLIST = $searcher.FindAll() 
```

_Tags: domain-wide, users_


## Domain password policy extraction

**Risk:** Captures domain-wide password policy affecting all tenants.

**Recommended fix:** Remove in shared domains or replace with fine-grained PSO scoped to the OU (if any).

**Occurrences:**

- **Line 1976** (pattern `Get-DefDomainPwdPol|default\s*domain\s*policy|Get-DomainPwdPol|DefDomainPwdPol`):

```powershell
  1972: 
  1973: 
  1974: 
  1975: 
  1976: Function Get-DefDomainPwdPol
  1977: {
  1978: 	[CmdletBinding()]
  1979: 	param (
  1980: 		[Parameter(
```

- **Line 2146** (pattern `Get-DefDomainPwdPol|default\s*domain\s*policy|Get-DomainPwdPol|DefDomainPwdPol`):

```powershell
  2142: 
  2143: 
  2144: 
  2145: 
  2146: Function Get-DomainPwdPol
  2147: {
  2148: 	[CmdletBinding()]
  2149: 	param (
  2150: 		[Parameter(
```

- **Line 3206** (pattern `Get-DefDomainPwdPol|default\s*domain\s*policy|Get-DomainPwdPol|DefDomainPwdPol`):

```powershell
  3202: 	Get-DirectoryUsersAll -Server $DomainBind -Path $Path
  3203: 	Get-DomainUsersStatus -Server $DomainBind -Path $Path
  3204: 	Get-DomainTrustsLatest -Server $DomainBind -Path $Path
  3205: 	Get-DCsInDomain -Domain $DomainBind -Path $Path
  3206: 	Get-DomainPwdPol -Server $ComputerName -Path $Path
  3207: 	Get-DefDomainPwdPol -Server $ComputerName -Path $Path
  3208: 	Get-DomainSecPol -Server $ComputerName -Path $Path
  3209: 	Get-FineGrainedPSO -Path $Path
  3210: 	Get-DomainSecPolBoolean -Server $DomainBind -Path $Path
```

- **Line 3207** (pattern `Get-DefDomainPwdPol|default\s*domain\s*policy|Get-DomainPwdPol|DefDomainPwdPol`):

```powershell
  3203: 	Get-DomainUsersStatus -Server $DomainBind -Path $Path
  3204: 	Get-DomainTrustsLatest -Server $DomainBind -Path $Path
  3205: 	Get-DCsInDomain -Domain $DomainBind -Path $Path
  3206: 	Get-DomainPwdPol -Server $ComputerName -Path $Path
  3207: 	Get-DefDomainPwdPol -Server $ComputerName -Path $Path
  3208: 	Get-DomainSecPol -Server $ComputerName -Path $Path
  3209: 	Get-FineGrainedPSO -Path $Path
  3210: 	Get-DomainSecPolBoolean -Server $DomainBind -Path $Path
  3211: 	Get-GPOReportall -Server $ComputerName -Path $Path
```

_Tags: non-scopable, policy_


## Fine-grained password settings (PSO) enumeration

**Risk:** May enumerate PSOs across the domain; unless you scope SearchRoot, this leaks other tenants' policies.

**Recommended fix:** Set DirectorySearcher.SearchRoot to the customer's OU; or query only msDS-PSOAppliesTo values under that OU.

**Occurrences:**

- **Line 2037** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2033: 	}
  2034: }
  2035: 
  2036: 
  2037: Function Get-FineGrainedPSO
  2038: {
  2039: 	[CmdletBinding()]
  2040: 	param (		
  2041: 		[Parameter(
```

- **Line 2054** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2050: 				
  2051: 		$root = [ADSI]''
  2052:         $searcher = new-object System.DirectoryServices.DirectorySearcher($root)
  2053: 
  2054: 		$searcher.filter = "(objectClass=msDS-PasswordSettings)"
  2055: 		
  2056: 		$searcher.PropertiesToLoad.AddRange(@("msds-lockoutduration","msds-minimumpasswordage","msds-lockoutobservationwindow","msds-maximumpasswordage","msds-lockoutthreshold","msds-passwordcomplexityenabled","msds-passwordhistorylength", "msds-minimumpasswordlength", "msds-psoappliesto", "whenchanged", "msds-passwordsettingsprecedence","cn"))
  2057: 		$searcher.PageSize = 1000
  2058: 		$PSOLIST = $searcher.FindAll() 
```

- **Line 2064** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2060: 		Write-ACTTDataLog -Message "Search Returned $($PSOLIST.Count) PSOs"
  2061: 		Write-Host "Search Returned $($PSOLIST.Count) PSOs"
  2062: 		$colPSOs = @()
  2063: 				
  2064: 		foreach ($PSO in $PSOLIST)
  2065: 		{
  2066:             #Caculation of timespan 
  2067:             $MaxPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-maximumpasswordage')" 
  2068:             $ObservationWindow  = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutobservationwindow')" 
```

- **Line 2067** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2063: 				
  2064: 		foreach ($PSO in $PSOLIST)
  2065: 		{
  2066:             #Caculation of timespan 
  2067:             $MaxPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-maximumpasswordage')" 
  2068:             $ObservationWindow  = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutobservationwindow')" 
  2069:             $MinPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-minimumpasswordage')" 
  2070:             $LockOutDuration    = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutduration')" 
  2071: 			#Build psCustomObject
```

- **Line 2068** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2064: 		foreach ($PSO in $PSOLIST)
  2065: 		{
  2066:             #Caculation of timespan 
  2067:             $MaxPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-maximumpasswordage')" 
  2068:             $ObservationWindow  = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutobservationwindow')" 
  2069:             $MinPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-minimumpasswordage')" 
  2070:             $LockOutDuration    = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutduration')" 
  2071: 			#Build psCustomObject
  2072:             
```

- **Line 2069** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2065: 		{
  2066:             #Caculation of timespan 
  2067:             $MaxPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-maximumpasswordage')" 
  2068:             $ObservationWindow  = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutobservationwindow')" 
  2069:             $MinPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-minimumpasswordage')" 
  2070:             $LockOutDuration    = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutduration')" 
  2071: 			#Build psCustomObject
  2072:             
  2073:             TRY
```

- **Line 2070** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2066:             #Caculation of timespan 
  2067:             $MaxPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-maximumpasswordage')" 
  2068:             $ObservationWindow  = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutobservationwindow')" 
  2069:             $MinPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-minimumpasswordage')" 
  2070:             $LockOutDuration    = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutduration')" 
  2071: 			#Build psCustomObject
  2072:             
  2073:             TRY
  2074:             {
```

- **Line 2075** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2071: 			#Build psCustomObject
  2072:             
  2073:             TRY
  2074:             {
  2075:                If($PSO.properties.'msds-psoappliesto' -eq $null)
  2076:                {
  2077:                EXCEPTION
  2078:                }
  2079:             }
```

- **Line 2082** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2078:                }
  2079:             }
  2080:             catch{
  2081:             $objUser = [PSCustomObject] @{
  2082: 					'PSOName'       = "$($PSO.properties.'cn')" 
  2083: 					'AppliesTo'     = "N/A - Not applied to any user/group"
  2084: 					'ObjectType'     = "N/A"
  2085: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2086: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
```

- **Line 2086** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2082: 					'PSOName'       = "$($PSO.properties.'cn')" 
  2083: 					'AppliesTo'     = "N/A - Not applied to any user/group"
  2084: 					'ObjectType'     = "N/A"
  2085: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2086: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
  2087: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2088: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2089: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2090: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
```

- **Line 2087** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2083: 					'AppliesTo'     = "N/A - Not applied to any user/group"
  2084: 					'ObjectType'     = "N/A"
  2085: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2086: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
  2087: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2088: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2089: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2090: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2091: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
```

- **Line 2088** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2084: 					'ObjectType'     = "N/A"
  2085: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2086: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
  2087: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2088: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2089: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2090: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2091: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2092: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
```

- **Line 2089** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2085: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2086: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
  2087: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2088: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2089: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2090: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2091: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2092: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
  2093: 					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
```

- **Line 2091** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2087: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2088: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2089: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2090: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2091: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2092: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
  2093: 					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
  2094: 					'msds-minimumpasswordlength'               = $($PSO.properties.'msds-minimumpasswordlength') 
  2095: 					'whenchanged'                              = $($PSO.properties.whenchanged) 
```

- **Line 2094** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2090: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2091: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2092: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
  2093: 					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
  2094: 					'msds-minimumpasswordlength'               = $($PSO.properties.'msds-minimumpasswordlength') 
  2095: 					'whenchanged'                              = $($PSO.properties.whenchanged) 
  2096: 				}
  2097:                 $colPSOs += $objUser
  2098:             Continue
```

- **Line 2095** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2091: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2092: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
  2093: 					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
  2094: 					'msds-minimumpasswordlength'               = $($PSO.properties.'msds-minimumpasswordlength') 
  2095: 					'whenchanged'                              = $($PSO.properties.whenchanged) 
  2096: 				}
  2097:                 $colPSOs += $objUser
  2098:             Continue
  2099:             }
```

- **Line 2101** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2097:                 $colPSOs += $objUser
  2098:             Continue
  2099:             }
  2100: 
  2101: 			foreach($dnApp in $PSO.properties.'msds-psoappliesto')
  2102: 			{
  2103: 				$ADObject=[ADSI]"LDAP://$dnApp" 
  2104: 				$objUser = [PSCustomObject] @{
  2105: 					'PSOName'       = "$($PSO.properties.'cn')" 
```

- **Line 2105** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2101: 			foreach($dnApp in $PSO.properties.'msds-psoappliesto')
  2102: 			{
  2103: 				$ADObject=[ADSI]"LDAP://$dnApp" 
  2104: 				$objUser = [PSCustomObject] @{
  2105: 					'PSOName'       = "$($PSO.properties.'cn')" 
  2106: 					'AppliesTo'     = "$($ADObject.Get('cn'))"
  2107: 					'ObjectType'     = "$($ADObject.Get('objectclass'))"
  2108: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2109: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
```

- **Line 2109** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2105: 					'PSOName'       = "$($PSO.properties.'cn')" 
  2106: 					'AppliesTo'     = "$($ADObject.Get('cn'))"
  2107: 					'ObjectType'     = "$($ADObject.Get('objectclass'))"
  2108: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2109: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
  2110: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2111: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2112: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2113: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
```

- **Line 2110** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2106: 					'AppliesTo'     = "$($ADObject.Get('cn'))"
  2107: 					'ObjectType'     = "$($ADObject.Get('objectclass'))"
  2108: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2109: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
  2110: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2111: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2112: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2113: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2114: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
```

- **Line 2111** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2107: 					'ObjectType'     = "$($ADObject.Get('objectclass'))"
  2108: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2109: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
  2110: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2111: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2112: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2113: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2114: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2115: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
```

- **Line 2112** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2108: 					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
  2109: 					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
  2110: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2111: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2112: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2113: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2114: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2115: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
  2116: 					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
```

- **Line 2114** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2110: 					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
  2111: 					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
  2112: 					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
  2113: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2114: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2115: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
  2116: 					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
  2117: 					'msds-minimumpasswordlength'               = $($PSO.properties.'msds-minimumpasswordlength') 
  2118: 					'whenchanged'                              = $($PSO.properties.whenchanged) 
```

- **Line 2117** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2113: 					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
  2114: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2115: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
  2116: 					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
  2117: 					'msds-minimumpasswordlength'               = $($PSO.properties.'msds-minimumpasswordlength') 
  2118: 					'whenchanged'                              = $($PSO.properties.whenchanged) 
  2119: 				}
  2120: 				# Add psCustomObject to Collection
  2121: 			$colPSOs += $objUser
```

- **Line 2118** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  2114: 					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
  2115: 					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
  2116: 					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
  2117: 					'msds-minimumpasswordlength'               = $($PSO.properties.'msds-minimumpasswordlength') 
  2118: 					'whenchanged'                              = $($PSO.properties.whenchanged) 
  2119: 				}
  2120: 				# Add psCustomObject to Collection
  2121: 			$colPSOs += $objUser
  2122: 
```

- **Line 3209** (pattern `\bmsDS-PasswordSettings\b|\bPSO\b|Fine-?Grained`):

```powershell
  3205: 	Get-DCsInDomain -Domain $DomainBind -Path $Path
  3206: 	Get-DomainPwdPol -Server $ComputerName -Path $Path
  3207: 	Get-DefDomainPwdPol -Server $ComputerName -Path $Path
  3208: 	Get-DomainSecPol -Server $ComputerName -Path $Path
  3209: 	Get-FineGrainedPSO -Path $Path
  3210: 	Get-DomainSecPolBoolean -Server $DomainBind -Path $Path
  3211: 	Get-GPOReportall -Server $ComputerName -Path $Path
  3212: 	Get-ServerUserRights -Server $ComputerName -Path $Path
  3213: 	Get-DomainGroupsMembersAll -Server $DomainBind -Path $Path
```

_Tags: policy, scope_


## Remediation Cookbook (copy/paste)
Below are drop-in snippets to help scope the script to a single customer's OU.

### DirectorySearcher (set base DN and scope)
```powershell
# Example: set to CustomerX OU
$base = "LDAP://OU=CustomerX,DC=shared,DC=local"
$root = [ADSI]$base
$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
$searcher.SearchScope = "Subtree"  # or [System.DirectoryServices.SearchScope]::Subtree
# apply your existing filters, e.g. users:
$searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
```

### Get-AD* with SearchBase
```powershell
$ou = "OU=CustomerX,DC=shared,DC=local"

Get-ADOrganizationalUnit -SearchBase $ou -LDAPFilter "(objectClass=organizationalUnit)" -SearchScope Subtree
Get-ADGroup -SearchBase $ou -LDAPFilter "(objectClass=group)" -SearchScope Subtree -Properties member
Get-ADUser -SearchBase $ou -LDAPFilter "(&(objectCategory=person)(objectClass=user))" -SearchScope Subtree -Properties samAccountName,displayName,whenChanged,lastLogonTimestamp
```

### OU ACLs only under customer OU
```powershell
$customerOUs = @("$ou")
foreach ($OU in $customerOUs) {
    Get-ACL -Path "AD:\$OU" | Select-Object -ExpandProperty Access | Where-Object {
        # Keep your existing filters if any
        $true
    }
}
```

### GPOs linked to the OU only
```powershell
$inherit = Get-GPInheritance -Target $ou
$linkedGpoIds = $inherit.GpoLinks | Where-Object { $_.Enabled } | ForEach-Object { $_.GpoId }
$linkedGpoIds | ForEach-Object {
    Get-GPO -Guid $_ | Get-GPOReport -ReportType Xml -Path (Join-Path $Path ("GPO_" + $_ + ".actt"))
}
```

### Disable non-scopable collectors in #region Main
- Remove or comment out: Get-ADDomainController, Trusts enumeration, Default Domain Password Policy, any forest/partitions queries.
