<#
'
'  ACTT Tool Extraction Code for Windows Server Analysis of Active Directory
'
'  
'  REVISION HISTORY:
' ------------------------------------------------------------------------------------
' Date(DD/MM/YYYY)		Responsible							Activity			
' ------------------------------------------------------------------------------------
' 26/01/2018		Ramakrishna, Shashank				Code Created
' 25/10/2019		Ramakrishna, Shashank				This script is an integrated version of R16 scripts of Windows and includes all bug fixes which were accomodated earlier
' 10/01/2021		Ramakrishna, Shashank				This script Updated for supporting Multi-Language support bug fix #2380
' 20/10/2021		Ramakrishna, Shashank 				Script added to extract data related to OU. Updated version to 18.1
' 22/04/2022		Antony, Godwin				    	Script updated to version 19.0 and hashed out ACTTDataLog message for OuPermissions extraction.
' 40/10/2022		Kosuri, Tarun Sai			    	Updated GroupMembers extraction code to reduce the extraction time.
' 04/04/2023        Kosuri, Tarun Sai                   Updated OUs extraction code to reduce the extraction time.
' 05/05/2023        Kosuri, Tarun Sai                   Added code to extract domain groupmembers informaion when executed on non domain controller.
' 05/06/2023        Kosuri, Tarun Sai                   Script updated to rename GPOReportAll.html wirh html extension to GPOReportAll.html.txt PB#2795.
' 22/08/2023		Kosuri, Tarun Sai					Script updated to handle AccountExpirationDate exceeding the limit of FromFileTime date PB# 1532470.
' 15/03/2024        Kosuri, Tarun Sai					Script updated to handle LastLoginTimeStamp exceeding the limit of FromFileTime date PB# 1774127.
' 24/03/2024        Kosuri, Tarun Sai					Script updated to apply filters to OUPermissions extraction with respect to the framework update PB# 1533562.
' 24/03/2024        Kosuri, Tarun Sai					Script updated to handle Unassigned PSOs in Active directory environment PB# 1774115.
' 14/12/2024      	Kosuri, Tarun Sai          			SCRIPT MODIFIED- Updated script to add ACTT system identifier file.
'
Notice:
' ------------------------------------------------------------------------------------
'	The purpose of this "read only" script is to download data that can be analyzed as part of our audit.  
'	We expect that you will follow your company's regular change management policies and procedures prior to running the script.
'	To the extent permitted by law, regulation and our professional standards, this script is provided "as is," 
'	without any warranty, and the Deloitte Network and its contractors will not be liable for any damages relating to this script or its use.  
'	As used herein, "we" and "our" refers to the Deloitte Network entity that provided the script to you, and the "Deloitte Network" refers to 
'	Deloitte Touche Tohmatsu Limited ("DTTL"), the member firms of DTTL, and each of their affiliates and related entities.
'
'	

#>


#region Parameters
[CmdletBinding()]
param(
	[Parameter(
	Mandatory=$false)]
	[String]$ForestFQDN = (Get-WmiObject win32_computersystem).Domain,  
	
	[Parameter(
			   Mandatory = $false)]
	[String]$ComputerName = (Get-WmiObject win32_computersystem).Name,
			
	[Parameter(
	Mandatory=$false)]
	[String]$Path = (Get-Location))
	
#endregion Parameters

#region Script Execution Code
<#
	This region of Script Code Sets Script Execution Options
	If the -Debug or -Verbose Common Parameters were Used.
	Needs to be at the top to set the Preferences before any Main Logic
	Code is run to have the options work correctly.
	
	Note:
		Use Set-StrictMode during Debugging Only!
		Comment out before releasing code to production.
		This will allow Non-Terminating Exceptions to be handled
		and allow the script to continue.
#>
$ScriptStartTime = Get-Date
Set-StrictMode -Version Latest

# Set a Script Level Variable for the Script Invocation Object.
$ScriptMyInvoc = $MyInvocation

# Configure Verbose and Debugging Options
if ($MyInvocation.BoundParameters.ContainsKey('Verbose'))
{
	$VerbosePreference = "Continue"
	Write-Verbose "Verbose Option Set: `$VerbosePreference Value: $VerbosePreference"
}
if ($MyInvocation.BoundParameters.ContainsKey('Debug'))
{
	$DebugPreference = "Continue"
	Write-Debug "Debug Option Set: `$DebugPreference Value: $DebugPreference `n`n"
}
#endregion  Script Execution Code

#region Global Variables
$Delim = '|^|'
#$TimeDate = get-date -format 'MM/dd/yyyy hh:mm:ss.fff tt'
#$ErrorList = @()
#$FilePermissions = @{ 'Path' = ''; 'AccessControlType' = ''; 'FileSystemRights' = ''; 'IdentityReference' = '' }
#$FilePermissionsList = @()
$ScriptVersion = '22.0p'
#endregion Global Variables
# Leave 2 Empty Lines before Declaring Functions for Comment Based Help to work properly



#region Functions

Function Get-ServerAuditPolicy
{
	<#
	.SYNOPSIS
		List audit policy on  DC - auditPolicy.actt
	
	.DESCRIPTION
		File: auditPolicy.actt
		NameSpace: '\root\rsop\computer'
		Query: 'SELECT * FROM RSOP_AuditPolicy'
		Report Fields: 'Category', 'Precedence', 'Failure', 'Success'

	.PARAMETER  Server
		

	.EXAMPLE
	

	.PARAMETER  Credential
		

	.EXAMPLE
		

	.INPUTS
		

	.OUTPUTS
		

	.NOTES
		

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#
	Try
	{
		Write-ACTTDataLog -Message 'List audit policy - auditPolicy.actt'
		
		$colAuditPolicies = @()
		$WMIQuery = Get-WmiObject -Namespace root\rsop\computer -Query 'SELECT * FROM RSOP_AuditPolicy' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$AuditPolicies = @('AuditPrivilegeUse', 'AuditDSAccess', 'AuditAccountLogon', 'AuditObjectAccess', 'AuditAccountManage',
			'AuditLogonEvents', 'AuditProcessTracking', 'AuditSystemEvents', 'AuditPolicyChange')
		$notDefinedvalue = $null
		If ($null -ne $WMIQuery)
		{
			ForEach ($Policy in $AuditPolicies)
			{
				$notDefinedvalue = $Policy
				ForEach ($item in $WMIQuery)
				{
					If ($Policy -eq $item.Category)
					{
						$objTemp = [PSCustomObject] @{
							'Category'   = $item.Category
							'Precedence' = $item.Precedence
							'Failure'    = $item.Failure
							'Success'    = $item.Success
						}
						
						# Add psCustomObject to Collection
						$colAuditPolicies += $objTemp
						$notDefinedvalue = $null
					}
										
				}

				if ($null -ne $notDefinedvalue)
				{
					$objTemp = [PSCustomObject] @{
							'Category'   = $Policy
							'Precedence' = 'Not Defined'
							'Failure'    = 'Not Defined'
							'Success'    = 'Not Defined'
						}
						
						# Add psCustomObject to Collection
						$colAuditPolicies += $objTemp
				}
				
				
			}
		}
		else
		{
			foreach ($Policy in $AuditPolicies)
			{
				$objTemp = [PSCustomObject] @{
					'Category'   = $Policy
					'Precedence' = 'Not Defined'
					'Failure'    = 'Not Defined'
					'Success'    = 'Not Defined'
				}
				$colAuditPolicies += $objTemp
			}
			
		}
		
		Write-host 'Exporting audit policy - auditPolicy.actt'
		Write-ActtFile -Data $colAuditPolicies -Path $(Join-Path $Path 'auditPolicy.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to list audit policy on local DC - auditPolicy.actt. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Could not List audit policy on $Server")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-ServerQuickFixes
{
	<#
	.SYNOPSIS
		List all quickfixes - quickfixes.actt
	
	.DESCRIPTION
		File: quickfixes.actt
		NameSpace: "\root\cimv2"
		Query: 'SELECT * FROM Win32_QuickFixEngineering'
		Report Fields: 'Caption', 'CSName', 'Description', 'FixComments', 'HotFixID', 'InstallDate', 'InstalledBy', 'InstalledOn', 'Name', 'ServicePackInEffect', 'Status'

	.PARAMETER  Server
		

	.EXAMPLE
	

	.PARAMETER  Credential
		

	.EXAMPLE
		

	.INPUTS
		

	.OUTPUTS
		quickfixes.actt

	.NOTES
		

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	
	Try
	{
		Write-ACTTDataLog -Message 'List all quickfixes - quickfixes.actt'
		
		$colQuickFixes = @()
		$WMIQuery = Get-WmiObject -Namespace root\cimv2 -Query 'SELECT * FROM Win32_QuickFixEngineering' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		
		If ($null -ne $WMIQuery)
		{
			ForEach ($item in $WMIQuery)
			{
				$objTemp = [PSCustomObject] @{
					'Caption' = $item.Caption
					'CSName' = $item.CSName
					'Description' = $item.Description
					'FixComments' = $item.FixComments
					'HotFixID' = $item.HotFixID
					'InstallDate' = $item.InstallDate
					'InstalledBy' = $item.InstalledBy
					'InstalledOn' = $item.InstalledOn
					'Name' = $item.Name
					'ServicePackInEffect' = $item.ServicePackInEffect
					'Status' = $item.Status
				}
				
				# Add psCustomObject to Collection
				$colQuickFixes += $objTemp
			}
		}
		else
		{
			$objTemp = [PSCustomObject] @{
				'Caption' = 'Not available'
				'CSName' = 'Not available'
				'Description' = 'Not available'
				'FixComments' = 'Not Available'
				'HotFixID' = 'Not Available'
				'InstallDate' = 'Not Available'
				'InstalledBy' = 'Not Available'
				'InstalledOn' = 'Not Available'
				'Name' = 'Not Available'
				'ServicePackInEffect' = 'Not Available'
				'Status' = 'Not Available'
			}
			$colQuickFixes += $objTemp
		}
		
		
		Write-ACTTDataLog -Message 'Exporting all quickfixes installed - quickfixes.actt'
		Write-host 'Exporting all quickfixes installed - quickfixes.actt'
		Write-ActtFile -Data $colQuickFixes -Path $(Join-Path $Path 'quickfixes.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to list all quickfixes on local DC - quickfixes.actt. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Could not List all quickfixes Assignments on $Server")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-ServerUserRights
{
	<#
	.SYNOPSIS
		List all User Rights Assignment on the server - userRights.actt
	
	.DESCRIPTION
		File: userRights.actt
		NameSpace: '\root\rsop\computer'
		Query: 'SELECT UserRight, Precedence, AccountList FROM RSOP_UserPrivilegeRight'
		Report Fields: 'UserRight', 'AccountList', 'Precedence'
		Need Remoting - User Rights Assignment needs to run "locally"

	.PARAMETER  Server
		

	.EXAMPLE
	

	.PARAMETER  Credential
		

	.EXAMPLE
		

	.INPUTS
		

	.OUTPUTS
		userRights.actt

	.NOTES
		

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[String]$Path)
	
	
	Try
	{
		Write-ACTTDataLog -Message 'List all User Rights Assignment on Domain Controller - userRights.actt'
		
		$colUserRightsAssignment = @()
		$WMIQuery = Get-WmiObject -Namespace root\rsop\computer -Query 'SELECT UserRight, Precedence, AccountList FROM RSOP_UserPrivilegeRight' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$UserRights = @('SeNetworkLogonRight', 'SeRemoteInteractiveLogonRight', 
                                                'SeRemoteShutdownPrivilege', 'SeBatchLogonRight', 'SeTcbPrivilege', 
                                                'SeServiceLogonRight', 'SeSecurityPrivilege', 'SeRestorePrivilege', 
                                                'SeShutdownPrivilege', 'SeTakeOwnershipPrivilege')
		$notDefinedvalue = $null
		If ($null -ne $WMIQuery)
		{			
				ForEach ($UserRight in $UserRights)
				{
					$notDefinedvalue = $UserRight
					ForEach ($item in $WMIQuery)
					{						
							If($UserRight -eq $item.UserRight)
							{
								ForEach ($AccountList in $item.AccountList)
								{
									$objTemp = [PSCustomObject] @{
									'UserRight' = $item.UserRight
									'AccountList' = $AccountList
									'Precedence' = $item.Precedence
									}
									$colUserRightsAssignment += $objTemp
								}								
					
							# Add psCustomObject to colFilePermissions
							
							$notDefinedvalue = $null
							}				
							  
					}
					if ($null -ne $notDefinedvalue)
						{
							$objTemp = [PSCustomObject] @{
								'UserRight' = $notDefinedvalue
								'AccountList' = 'Not Defined'
								'Precedence' = 'Not Defined'
								}
					
								# Add psCustomObject to colFilePermissions
								$colUserRightsAssignment += $objTemp
						}
					
				}			
			
		}
		else
		{
			Foreach ($right in $UserRights)
			{
				$objTemp = [PSCustomObject] @{
					'UserRight'   = $right
					'AccountList' = 'Not Defined'
					'Precedence'  = 'Not Defined'
				}
				
				# Add psCustomObject to colFilePermissions
				$colUserRightsAssignment += $objTemp
			}
		}
		
		
	Write-ACTTDataLog -Message 'Exporting all User Rights Assingment on Server - userRights.actt'
		Write-host 'Exporting all User Rights Assingment on Server - userRights.actt'
		Write-ActtFile -Data $colUserRightsAssignment -Path $(Join-Path $Path 'userRights.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to list all User Rights Assignments. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Could not List all User Rights Assignments on $Server")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-DomainComputersAll
{
	<#
	.SYNOPSIS
		List all Computer objects in domain - Computers.actt
	
	.DESCRIPTION
		File: Computers.actt
		Report Fields: 'SamAccountName', 'Name', 'Description', 'LastLogon', 'OperatingSystem', 'OperatingSystemVersion', 'OperatingSystemServicePack', 'DNSHostName', 'DistinguishedName'

	.PARAMETER  Server
		

	.EXAMPLE
	

	.PARAMETER  Credential
		

	.EXAMPLE
		

	.INPUTS
		

	.OUTPUTS
		Computers.actt

	.NOTES
		

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Computer objects in domain - Computers.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Computer objects in domain - Computers.actt'
	<#
        File: Computers.actt
        Report Fields: 'SamAccountName', 'Name', 'Description', 'LastLogon', 'OperatingSystem', 'OperatingSystemVersion', 'OperatingSystemServicePack', 'DNSHostName', 'DistinguishedName'
    #>
		Write-Host 'Searching All Computer Objects'
		$AllComputerObjects = Get-ADComputer -Server $Server -Filter * -Properties SamAccountName, Name, Description, LastLogon, OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, DNSHostName, DistinguishedName -ErrorAction Stop
		$colComputers = @()
		
		foreach ($Computer in $AllComputerObjects)
		{
			#Build ComputerObject
			$objComp = [PSCustomObject] @{
				'SamAccountName' = $Computer.SamAccountName
				'Name' = $Computer.Name
				'Description' = $Computer.Description
				'LastLogon' = $Computer.LastLogon
				'OperatingSystem' = $Computer.OperatingSystem
				'OperatingSystemVersion' = $Computer.OperatingSystemVersion
				'OperatingSystemServicePack' = $Computer.OperatingSystemServicePack
				'DNSHostName' = $Computer.DNSHostName
				'DistinguishedName' = $Computer.DistinguishedName
			}
			
			# Add objDC to colDCs
			$colComputers += $objComp
		}
		
		Write-ACTTDataLog -Message 'Exporting All Computer Objects - Computers.actt'
		Write-host 'Exporting All Computer Objects - Computers.actt'
		Write-ActtFile -Data $colComputers -Path $(Join-Path $Path 'Computers.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all computer objects in the domain. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Computer objects in domain')
		$swExceptionLog.WriteLine($Error[0])
	}
}



Function Get-OuPermissions
{
	
		<#
	.SYNOPSIS
		Get's OU permissions for AD audit procedures
	.DESCRIPTION
		Exports a CSV of OU Permissions for AD audit procedures. Does not include permissions for standard AD privileged groups 
		or special identities such as "Self" or "CREATOR OWNER".
	#>
	#region [SCRIPT PARAMETERS] -----------------------------------------------------------------------
	[CmdletBinding()]
	param (
			[Parameter(
					   Mandatory = $true)]
			[String]$Domain,
			[Parameter(
					   Mandatory = $true)]
			[String]$Path)
	#endregion [SCRIPT PARAMETERS] -----------------------------------------------------------------------
	#region [Initializations] -----------------------------------------------------------------------
	#$ErrorActionPreference = 'SilentlyContinue'
	Try
	{
		Write-ACTTDataLog -Message 'List get-OUPermission.actt'
		
		#endregion [Initializations] -----------------------------------------------------------------------

		#region [Declarations] -----------------------------------------------------------------------

		#$outputFileName = "OU_Permissions" --Prakash
		$dn=$Domain
		Write-ACTTDataLog -Message 'Get-OUPermissions - OUPermissions.actt'


		$excludedIdentities = @(
			'Enterprise Admins',
			'Schema Admins',
			'Domain Admins',
			'Administrators',
			'Account Operators',
			'Server Operators',
			'CREATOR OWNER',
			'Self'
		)

		$excludedAccessRights = @(
			'ReadProperty',
			'GenericRead',
			'GenericExecute',
			'ReadProperty, GenericExecute',
			'ReadControl',
			'ListChildren',
			'ListChildren, ReadProperty, ListObject'
		)
	    $IncludedAccessRights = @(
                'GenericAll',
                'GenericWrite',
                'WriteProperty',
                'ExtendedRight'
		    )


		#endregion [Declarations] -----------------------------------------------------------------------

		    #region [Functions] -----------------------------------------------------------------------

		#region AD Functions

		function Get-NETBiosName ( $dn, $ConfigurationNC ) 
		{ 
			try 
			{ 
				$Searcher = New-Object System.DirectoryServices.DirectorySearcher  
				$Searcher.SearchScope = "subtree"  
				$Searcher.PropertiesToLoad.Add("nETBIOSName")| Out-Null 
				$Searcher.SearchRoot = "LDAP://cn=Partitions,$ConfigurationNC" 
				$Searcher.Filter = "(nCName=$dn)" 
				$NetBIOSName = ($Searcher.FindOne()).Properties.Item("nETBIOSName") 
				Return $NetBIOSName 
			} 
			catch 
			{ 
				Return $null 
			} 
		}
		function Format-DistinguishedName {
			[CmdletBinding()]
			param (
				# Parameter help description
				[Parameter(ValueFromPipeline)]
				[string[]]
				$Path,

				[Parameter(Mandatory=$false)]
				[ValidateSet("DistinguishedName","CanonicalName")]
				[string]
				$Format = "CanonicalName",

				[switch]
				$ExcludeDomain,

				[switch]
				$ExcludeCN
			)
			
			begin {
				
			}
			
			process {
				$split = $Path.Split(',') |
					#Where-Object { $ExcludeDomain -eq $true -and $_ -notlike 'dn=*'} |
					Where-Object { $ExcludeCN -eq $false -or $_ -notlike 'cn=*' }

				$arr = (@(($split | Where-Object {$_ -notmatch 'DC=' }) | ForEach-Object { $_.Substring(3)}))
				[array]::Reverse($arr)


				$base = $arr -join '/'

				$dn = ($split | Where-Object { $_  -Match 'dc=' } | ForEach-Object { $_.replace('DC=', '') }) -join '.'

				if ($ExcludeDomain -eq $false) {
					$return = $dn + '/' + $base
				}

				Write-Output $return

			}
			
			end {
				
			}
		}

		#endregion AD Functions


		#endregion [Functions] -----------------------------------------------------------------------

		#-----------------------------------------------------------[Execution]------------------------------------------------------------

		# This array will hold the report output.
		$report = @()
		# Build Output Filename
		$rootDSE = [adsi]"LDAP://RootDSE"
		$configNamingContext = $rootDSE.configurationNamingContext
		$domainD=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		$domainDN = 'dc=' + $domainD.Name.Replace('.',',dc=')
		$netBiosName = Get-NETBiosName $domainDN $configNamingContext

#Write-ACTTDataLog -Message 'List get-OUPermission.actt -Prakash91'

# Hide the errors for a couple duplicate hash table keys.
$schemaIDGUID = @{}
### NEED TO RECONCILE THE CONFLICTS ###
$ErrorActionPreference = 'SilentlyContinue'

try{
$schemaIDGUID = @{}
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID | ForEach-Object { $schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}

$ErrorActionPreference = 'Continue'
}
catch{
Write-ACTTDataLog -Message 'List get-OUPermission.actt -Exception'

}


# Get a list of all OUs.  Add in the root containers for good measure (users, computers, etc.).

$OUs  = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
$OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
[String]$DomainDN = ''
#$ForestFQDN.split('.') | %{ $DomainDN="DN=$($_),$DomainDN"}
$DomainDN = "DC="+ $ForestFQDN.Replace('.',',DC=')
$OUs += Get-ADObject -Server $ComputerName -SearchBase $DomainDN -SearchScope OneLevel -LDAPFilter '(objectClass=container)'| Select-Object -ExpandProperty DistinguishedName

#$excludedObjectGuids = $excludedIdentities | ForEach-Object { $schemaIDGUID | Where-Object { $_.Value -eq $_ } | Select-Object -Property Key }
# $lapsAttrGuid = $schemaIDGUID.GetEnumerator() | Where-Object { $_.Value -eq 'ms-Mcs-AdmPwd' }


$Path = Join-Path $Path 'OUPermissions.actt'
$Header = "[AccessControlType] NVARCHAR(MAX)|^|[ActiveDirectoryRights] NVARCHAR(MAX)|^|[identityName] NVARCHAR(MAX)|^|[IdentityReference] NVARCHAR(MAX)|^|[InheritanceFlags] NVARCHAR(MAX)|^|[InheritanceType] NVARCHAR(MAX)|^|[inheritedObjectTypeName] NVARCHAR(MAX)|^|[IsInherited] NVARCHAR(MAX)|^|[objectTypeName] NVARCHAR(MAX)|^|[organizationalUnit] NVARCHAR(MAX)|^|[organizationalUnitCN] NVARCHAR(MAX)|^|[PropagationFlags] NVARCHAR(MAX)"
$swriter = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::Unicode)
$swriter.WriteLine($Header)
$swriter.Close()

# Need Guid so we can include earlier in the filter pipleline to optimize processing.
$lapsAttrGuid = '';

foreach ($guid in $schemaIDGUID.GetEnumerator()) {
    if($guid.Value -eq 'ms-Mcs-AdmPwd' ){
        $lapsAttrGuid = $guid.Key.ToString()
        break
    }
}

$i = 0
$total = $OUs.Count
$secRemaining = -1
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$stb = [System.Text.StringBuilder]""

# Loop through each of the OUs and retrieve their permissions.
ForEach ($OU in $OUs) {
   
    $i++
    Write-Progress -Activity "Exporting OU Permissions" -Status "($i of $total)" -CurrentOperation "Exporting $OU" -PercentComplete ($i/$total*100) -SecondsRemaining $secRemaining
   
    $canonicalName = @{label='organizationalUnitCN';expression={(Format-DistinguishedName -Path $OU)}}
    $ACLs = Get-ACL -Path "AD:\$OU" | Select-Object -ExpandProperty Access | Where({
                           ($_.ActiveDirectoryRights -notin $excludedAccessRights -or $_.objectType.ToString() -eq $lapsAttrGuid) -and ( $_.IdentityReference -notlike 'NT AUTHORITY\*' -and $_.IdentityReference -notlike 'BUILTIN\*' -and $_.identityReference -notlike 'S-1-*' )})|
                           Select-Object $canonicalName,
                           @{name='organizationalUnit';expression={$OU}}, `
						   IdentityReference,
						   AccessControlType,
						   ActiveDirectoryRights,
						   @{name='inheritedObjectTypeName';expression={$schemaIDGUID[$_.inheritedObjectType]}}, `
						   @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID[$_.objectType]}}}, `
						   @{name='identityName';expression={if ($_.identityReference -like '*\*') { ($_.identityReference).ToString().Split('\')[1] } Else { $_.identityReference } }}, `
						   InheritanceType,
						   InheritanceFlags,
						   PropagationFlags,
						   IsInherited | Where( { ($_.AccessControlType -eq 'Allow') -and ( $_.objectTypeName -in 'All', 'Member', 'Membership', 'User-Account-Control', 'User-Account-Restrictions', 'Account-Expires','User-Force-Change-Password')  -and ( $_.inheritedObjectTypeName -in 'User','Group' -or $_.inheritedObjectTypeName -eq $null ) -and ($_.InheritanceType -in 'All','Descendants')} )
      [void]$stb.Clear()
      if($ACLs -eq $null)
      {
        continue
      }
      ForEach($Properties in $ACLs)
      {
        [void]$stb.Append($Properties.AccessControlType).Append('|^|')
        [void]$stb.Append($Properties.ActiveDirectoryRights).Append('|^|')
        [void]$stb.Append($Properties.identityName).Append('|^|')
        [void]$stb.Append($Properties.IdentityReference).Append('|^|')
        [void]$stb.Append($Properties.InheritanceFlags).Append('|^|')
        [void]$stb.Append($Properties.InheritanceType).Append('|^|')
        [void]$stb.Append($Properties.inheritedObjectTypeName).Append('|^|')
        [void]$stb.Append($Properties.IsInherited).Append('|^|')
        [void]$stb.Append($Properties.objectTypeName).Append('|^|')
        [void]$stb.Append($Properties.organizationalUnit).Append('|^|')
        [void]$stb.Append($Properties.organizationalUnitCN).Append('|^|')
        [void]$stb.Append($Properties.PropagationFlags).AppendLine()
      }
       # $stb.ToString() | Out-File -Append -FilePath $(Join-Path $Path 'OUPermissions.actt')
        $swriter = New-Object System.IO.StreamWriter($Path, $true, [System.Text.Encoding]::Unicode)
        $swriter.WriteLine($stb.ToString().Trim())
        $swriter.Close()
        [void]$stb.Clear()
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
		
		$secRemaining = [Math]::Round(($sw.Elapsed.Seconds / $i) * ($total - $i) )
		}
		Write-ACTTDataLog -Message 'Exporting Permissions - OUPermissions.actt'
		Write-host 'Exporting Permissions - OUPermissions.actt'
	}
	Catch
	{
		#Some error occurred attempting to List all computer objects in the domain. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all OU Permissions')
		$swExceptionLog.WriteLine($Error[0])
 
	}
}


Function Get-DCsInDomain
{
	# Function uses a Domain object from a Forest Object
	[CmdletBinding()]
	param (
		
		[Parameter(
				   Mandatory = $false)]
		[Object]$Domain,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	Try
	{
		Write-ACTTDataLog -Message 'Get Domains Controllers in the Domain - DomainControllers.actt'
		Write-Host 'Searching Domain Controllers'
		$AllDomainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
		$colDomainControllers = @()
		
		
		ForEach ($attr in $AllDomainControllers)
		{
			$objDC = [PSCustomObject] @{
				'Forest' = $attr.Forest
				'Domain' = $attr.Domain
				'HostName' = $attr.HostName
			}
			$colDomainControllers += $objDC
		}
		
		
		Write-ACTTDataLog -Message 'Exporting Domain Controllers - DomainControllers.actt'
		Write-host 'Exporting Domain Controllers - DomainControllers.actt'
		Write-ActtFile -Data $colDomainControllers -Path $(Join-Path $Path 'DomainControllers.actt')
		
	}
	catch
	{
		$swExceptionLog.WriteLine('Error - Could not list all Domain Controllers')
		$swExceptionLog.WriteLine($Error[0])
	}
	
}


Function Get-GPOReportall
{
	
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	
	Try
	{
		Write-ACTTDataLog -Message 'Get All Domain Group Policy Objects Settings GPOReportAll.html'
		
		Get-GPOReport -All -ReportType html -Path $(Join-Path $Path 'GPOReportAll.html.txt') -Server $Server 
				
		Write-ACTTDataLog -Message 'Exporting All Domain GPOs - GPOReportAll.html'
		Write-host 'Exporting All Domain GPOs - GPOReportAll.html'
		
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Security Policies - Numeric. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not extract all Domain GPOs')
		#$swExceptionLog.WriteLine($WMIError[0])
	}
}


Function Get-TimeDate
{
	<#
	.SYNOPSIS
		Returns a formatted Date-Time object
	
	.DESCRIPTION
		This function will return a date-time object formatted.


	.EXAMPLE
		Get-Date


	.OUTPUTS
		Date-Time object

	.NOTES
		TODO:
		

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	Get-Date -Format 'MM/dd/yyyy hh:mm:ss.fff tt'
}


Function Write-ActtFile
{
	
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0,
				   Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true,
				   HelpMessage = 'Data to be written to Actt File')]
		[ValidateNotNullOrEmpty()]
		[System.Object]$Data,
		[Parameter(Position = 1,
				   Mandatory = $true,
				   HelpMessage = 'Full Path of the Actt FIle')]
		[ValidateNotNullOrEmpty()]
		[string]$Path,
		[Parameter(Position = 2,
				   Mandatory = $false)]
		[string]$Delimiter = '|^|'
	)
	
	$VerbosePreference = 'Continue'
	Try
	{
		# Create StreamWriter
		$SW = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::Unicode)
		
		# Write Header
		$Header = ''
		$Properties = @()
		$Properties += ($Data[0] | Get-Member | Where-Object { $_.MemberType -eq 'NoteProperty' }).Name
		For ($i = 0; $i -lt $Properties.Count; $i++)
		{
			If ($i -eq ($Properties.Count - 1))
			{
				$Header += '[' + $($Properties[$i]) + '] NVARCHAR(MAX)'
			}
			Else
			{
				$Header += '[' + $($Properties[$i]) + '] NVARCHAR(MAX)' + $Delimiter
			}
		}
		$SW.WriteLine($Header)
		
		
		# Parse through dataset and write out to actt log file
		ForEach ($Result in $Data)
		{
			$Record = ''
			
			For ($i = 0; $i -lt $Properties.Count; $i++)
			{
				# Grab Current Property
				$Prop = $Properties[$i]
				#check if working on last property so we do not add the delimiter to the end of the record.
				If ($i -eq ($Properties.Count - 1))
				{
					#Check for $null in $Result.Prop -- Still need to check for arrays in properties.
					If ($null -ne $Result.$Prop)
					{
						$Record += $Result.$Prop
					}
				}
				Else
				{
					If ($null -ne $Result.$Prop)
					{
						$Record += $Result.$Prop.ToString() + $Delimiter
					}
					Else
					{
						$Record += $Delimiter
					}
				}
			}
			$SW.WriteLine($Record)
		}
	}
	
	Catch
	{
		#Some error occurred attempting to write the extract .actt file. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Writing Export .actt File $Path")
		$swExceptionLog.WriteLine($Error[0])
	}
	
	Finally
	{
		$SW.close()
	}
}



Function Write-ActtFileContent
{
	
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0,
				   Mandatory = $true,
				   ValueFromPipelineByPropertyName = $true,
				   HelpMessage = 'Data to be written to Actt File')]
		[ValidateNotNullOrEmpty()]
		[System.Object]$Data,
		[Parameter(Position = 1,
				   Mandatory = $true,
				   HelpMessage = 'Full Path of the Actt FIle')]
		[ValidateNotNullOrEmpty()]
		[string]$Path,
		[Parameter(Position = 2,
				   Mandatory = $false)]
		[string]$Delimiter = '|^|'
	)
	
	$VerbosePreference = 'Continue'
	Try
	{
		# Create StreamWriter
		$SW = New-Object System.IO.StreamWriter($Path, $true, [System.Text.Encoding]::Unicode)
		
		# Write Header
		$Header = ''
		$Properties = @()
		$Properties += ($Data[0] | Get-Member | Where-Object { $_.MemberType -eq 'NoteProperty' }).Name
		<#For ($i = 0; $i -lt $Properties.Count; $i++)
		{
			If ($i -eq ($Properties.Count - 1))
			{
				$Header += '[' + $($Properties[$i]) + '] NVARCHAR(MAX)'
			}
			Else
			{
				$Header += '[' + $($Properties[$i]) + '] NVARCHAR(MAX)' + $Delimiter
			}
		}
		$SW.WriteLine($Header)#>
		
		
		# Parse through dataset and write out to actt log file
		ForEach ($Result in $Data)
		{
			$Record = ''
			
			For ($i = 0; $i -lt $Properties.Count; $i++)
			{
				# Grab Current Property
				$Prop = $Properties[$i]
				#check if working on last property so we do not add the delimiter to the end of the record.
				If ($i -eq ($Properties.Count - 1))
				{
					#Check for $null in $Result.Prop -- Still need to check for arrays in properties.
					If ($null -ne $Result.$Prop)
					{
						$Record += $Result.$Prop
					}
				}
				Else
				{
					If ($null -ne $Result.$Prop)
					{
						$Record += $Result.$Prop.ToString() + $Delimiter
					}
					Else
					{
						$Record += $Delimiter
					}
				}
			}
			$SW.WriteLine($Record)
		}
	}
	
	Catch
	{
		#Some error occurred attempting to write the extract .actt file. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Writing Export .actt File $Path")
		$swExceptionLog.WriteLine($Error[0])
	}
	
	Finally
	{
		$SW.close()
	}
}


Function Get-DomainTrustsAll
{
	<#
	.SYNOPSIS
		List Domain Trusts and their status - trusts.actt
	
	.DESCRIPTION
		File: trusts.actt
        NameSpace: '\root\MicrosoftActiveDirectory'
        Query: 'SELECT * FROM Microsoft_DomainTrustStatus'
        Report Fields: 'TrustedDomain', 'TrustDirection', 'TrustType', 'TrustAttributes', 'TrustedDCName', 'TrustStatus', 'TrustIsOK'

	.PARAMETER  Server
		

	.EXAMPLE
	

	.PARAMETER  Credential
		

	.EXAMPLE
		

	.INPUTS
		

	.OUTPUTS
		trusts.actt

	.NOTES
		

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	Try
	{
		Write-ACTTDataLog -Message 'List Domain Trusts and their status - trusts.actt'
		
		$colTrusts = @()
		$ADDomainTrusts = Get-ADObject -Server $Server -Filter { ObjectClass -eq 'trustedDomain' } -Properties *
		
		ForEach ($Trust in $ADDomainTrusts)
		{
			# WMI Request using the trustmon WMI provider
			$TargetName = $Trust.trustPartner
			$WMIStatus = Get-WmiObject -Namespace root\MicrosoftActiveDirectory -Class Microsoft_DomainTrustStatus -ComputerName $Server -Filter "TrustedDomain='$TargetName'" -ErrorAction SilentlyContinue -ErrorVariable WMIError
			
			if (-not ($WMIError))
			{
				$objStatus = [PSCustomObject] @{
					'TrustedDomain'   = $WMIStatus.TrustedDomain
					'TrustDirection'  = $WMIStatus.TrustDirection
					'TrustType'	      = $WMIStatus.TrustType
					'TrustAttributes' = $WMIStatus.TrustAttributes
					'TrustedDCName'   = $WMIStatus.TrustedDCName
					'TrustStatus'	  = $WMIStatus.TrustStatus
					'TrustIsOK'	      = $WMIStatus.TrustIsOK
				}
				$colTrusts += $objStatus
			}
		}
		
		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List Domain Trusts and their status. Writing error $errorlist
		$swExceptionLog.WriteLine("Error while verifying trust with domain '$targetName': $($_.Exception.Message)")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-DomainTrustsLatest
{
		
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	Try
	{
		Write-ACTTDataLog -Message 'List Domain Trusts and their status - trusts.actt'
		
		$colTrusts = @()
		$ADDomainTrusts = Get-ADTrust -Server $Server -Filter *
				
		ForEach ($Trust in $ADDomainTrusts)
		{
			# WMI Request using the trustmon WMI provider
			#$TargetName = $Trust.trustPartner
			#$WMIStatus = Get-WmiObject -Namespace root\MicrosoftActiveDirectory -Class Microsoft_DomainTrustStatus -ComputerName $Server -Credential $Credential -Filter "TrustedDomain='$TargetName'" -ErrorAction SilentlyContinue -ErrorVariable WMIError
			
			#if (-not ($WMIError))
			
				$objStatus = [PSCustomObject] @{
					'TrustedDomain' = $Trust.Name
					'TrustDirection' = $Trust.Direction
					'TrustType' = $Trust.TrustType
					'TrustAttributes' = $Trust.TrustAttributes
#					'TrustedDCName' = $Trust.TrustedDCName
#					'TrustStatus' = $Trust.TrustStatus
#					'TrustIsOK' = $Trust.TrustIsOK
				}
				$colTrusts += $objStatus
			
		}
		
		Write-ACTTDataLog -Message 'Exporting Domain Trusts and their status - trusts.actt'
		Write-host 'Exporting Domain Trusts and their status - trusts.actt'
		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List Domain Trusts and their status. Writing error $errorlist
		$swExceptionLog.WriteLine("Error while verifying trust with domain '$Server': $($_.Exception.Message)")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Write-ACTTDataLog
{
	
	# Uses Global StreamWriter object $swACTTDataLog
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0,
				   Mandatory = $true,
				   HelpMessage = 'Data to be written to ACTTDataLog File')]
		[ValidateNotNullOrEmpty()]
		[string]$Message
	)
	
	# Write log entry to $Path
	$swACTTDataLog.WriteLine($(Get-TimeDate) + ': ' + $Message)
}

Function Write-ACTTConfigSettings
{

	# Uses Global StreamWriter object $swACTTDataLog
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0,
				   Mandatory = $true,
				   HelpMessage = 'Setting to be written to ACTT_CONFIG_SETTINGS.actt')]
		[ValidateNotNullOrEmpty()]
		[string]$Setting,
		[Parameter(Position = 1,
				   Mandatory = $true,
				   HelpMessage = 'Setting Value to be written to ACTT_CONFIG_SETTINGS.actt')]
		[ValidateNotNullOrEmpty()]
		[string]$Value
	)
	
	# Write log entry to $Path
	
	$swConfigSettings.WriteLine($Setting + $Delim + $Value)
}

Function Get-ConfigSettings
{
	Try
	{
	
		$WMIOSQuery = Get-WmiObject -Namespace root\cimv2 -Query 'SELECT * FROM Win32_OperatingSystem' -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$WMIComputerQuery = Get-WmiObject -Namespace root\cimv2 -Query 'SELECT * FROM Win32_ComputerSystem' -ErrorAction SilentlyContinue -ErrorVariable WMIError
		
		# This could be just a Hash Table instead...
		If ($null -ne $WMIOSQuery)
		{
			$User = $env:USERDOMAIN + '\' + $env:USERNAME
			$FQDN = [System.Net.DNS]::GetHostByName('').HostName
			Write-ACTTConfigSettings -Setting 'ProductType' -Value $WMIOSQuery.ProductType
			Write-ACTTConfigSettings -Setting 'Version' -Value $WMIOSQuery.Version
			Write-ACTTConfigSettings -Setting 'ServicePackMajorVersion' -Value $WMIOSQuery.ServicePackMajorVersion
			Write-ACTTConfigSettings -Setting 'ServicePackMinorVersion' -Value $WMIOSQuery.ServicePackMinorVersion
			Write-ACTTConfigSettings -Setting 'Caption' -Value $WMIOSQuery.Caption
			Write-ACTTConfigSettings -Setting 'Fully Qualified Domain Name' -Value $FQDN
			Write-ACTTConfigSettings -Setting 'Domain Name' -Value $WMIComputerQuery.Domain
			Write-ACTTConfigSettings -Setting 'ServerName' -Value $WMIComputerQuery.Name
			Write-ACTTConfigSettings -Setting 'UserName' -Value $User
			Write-ACTTConfigSettings -Setting 'Extract Script Version' -Value $ScriptVersion
			
		}
	}
  
	Catch
	{
		#Some error occurred attempting to Export Environment of the System performing the audit data extraction - ACTT_CONFIG_SETTINGS.actt. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Export Environment of the System performing the audit data extraction')
		$swExceptionLog.WriteLine($Error[0])
	}
}

Function Get-HostAndUserDetails
{
  Try
  {
    Write-ACTTDataLog -Message 'Get Host and User name currently logged in - HostandUserName.actt'
   
    $colHostandUserName = @()
    $WMIQuery = Get-WmiObject -Namespace root\cimv2 -Query 'SELECT * FROM Win32_ComputerSystem' -ErrorAction SilentlyContinue -ErrorVariable WMIError
    
    If ($null -ne $WMIQuery)
    {
      $objTemp = [PSCustomObject] @{
        'Name' = $WMIQuery.Name
        'UserName' = $env:USERNAME
      }

      # Add psCustomObject to Collection
      $colHostandUserName += $objTemp
    }
    
    Write-host 'Exporting Host and User name currently logged in - HostandUserName.actt'
    Write-ActtFile -Data $colHostandUserName -Path $(Join-Path $Path 'HostandUserName.actt')
  }
  
  Catch
  {
    #Some error occurred attempting to Get Host and User name currently logged in - HostandUserName.actt. Writing error $errorlist
    $swExceptionLog.WriteLine('Error - Get Host and User name currently logged in')
    $swExceptionLog.WriteLine($Error[0])
  }
}

Function Get-DomainOUsAll
{	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	
	Try
	{
		Write-ACTTDataLog -Message 'List all OUs in Domain - OU.actt'
		<#
		File: OU.actt
		Report Fields: 'Name', 'objectClass', 'Description', 'WhenCreated', 'LinkedGroupPolicyObjects', 'DistinguishedName'
		Pass in Domain, Domain Controller, File, Report Fields
		#>
		Write-Host 'Searching All OUs'
		$AllOUs = Get-ADOrganizationalUnit -Server $Server -Filter * -Properties Name, objectClass, Description, WhenCreated, LinkedGroupPolicyObjects, DistinguishedName -ErrorAction Stop
		
		$colOUs = @()
		
		foreach ($OU in $AllOUs)
		{
			#Build ComputerObject
			$objOU = [PSCustomObject] @{
				'Name' = $OU.Name
				'objectClass' = $OU.objectClass
				'Description' = $OU.Description
				'WhenCreated' = $OU.WhenCreated
				'LinkedGroupPolicyObjects' = $OU.LinkedGroupPolicyObjects
				'DistinguishedName' = $OU.DistinguishedName
			}
			
			# Add objDC to colDCs
			$colOUs += $objOU
		}
		
		Write-ACTTDataLog -Message 'Exporting OUs - OU.actt'
		Write-host 'Exporting OUs - OU.actt'
		Write-ActtFile -Data $colOUs -Path $(Join-Path $Path 'OU.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all OUs. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all OUs in domain')
		$swExceptionLog.WriteLine($Error[0])
	}
}

Function Get-DomainGroupsAll
{
	<#
	.SYNOPSIS
		List all Domain Groups - groups.actt
	
	.DESCRIPTION
		

	.PARAMETER  Server
		

	.EXAMPLE
	

	.PARAMETER  Credential
		

	.EXAMPLE
		

	.INPUTS
		

	.OUTPUTS
		groups.actt

	.NOTES
		

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Domain Groups - groups.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Domain Groups - groups.actt'
	<#
        File: groups.actt
        Report Fields: 'GroupName', 'GroupSID', 'Description'
    #>
		Write-Host 'Searching All Domain Groups'
		$AllDomainGroups = Get-ADGroup -Server $Server -Filter * -Properties SamAccountName, ObjectSID, Description -ErrorAction Stop
		$colGroups = @()
		
		foreach ($DGroup in $AllDomainGroups)
		{
			try
			{
				#Build GroupObject
				$objGroup = [PSCustomObject] @{
					'GroupName'   = $DGroup.SamAccountName
					'GroupSID'    = $DGroup.ObjectSID
					'Description' = $DGroup.Description
				}
				
				# Add objDC to colDCs
				$colGroups += $objGroup
			}
			Catch
			{
				$swExceptionLog.WriteLine($Error[0])
				continue
			}
			
		}
		
		Write-ACTTDataLog -Message 'Exporting All Domain Groups - groups.actt'
		Write-host 'Exporting All Domain Groups - groups.actt'
		Write-ActtFile -Data $colGroups -Path $(Join-Path $Path 'groups.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Groups with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Groups')
		$swExceptionLog.WriteLine($Error[0])
	}
}

#tarun
function Get-DomainGroupsMembersAll {
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
    #List all members in Domain Groups - groupmembers.actt
	Try{
            $Path = Join-Path $Path 'groupmembers.actt'
			Write-ACTTDataLog -Message 'List all Domain Group Members - groupmembers.actt'
		<#
			File: groupmembers.actt
			Report Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'
		#>
            Write-Host 'Searching All Domain Group Members'
            $AllDomainGroups = Get-ADGroup -Server $Server -Filter * -Properties SamAccountName, ObjectSID ,members -ErrorAction Stop
			$Header = "[GroupName] NVARCHAR(MAX)|^|[GroupSID] NVARCHAR(MAX)|^|[Member] NVARCHAR(MAX)|^|[objectSID] NVARCHAR(MAX)"
            $SW = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::Unicode)
            $SW.WriteLine($Header)
            $SW.Close()
            Write-Host 'Found '$AllDomainGroups.count' Groups in the domain. Extracting group members information in the background. Kindly note that the extraction time depends on the size of AD'
			foreach($DGroup in $AllDomainGroups){
				Try{	
						$GroupMembersObj = @()
						$GroupMembers = Get-ADGroupMember -Identity $DGroup -ErrorAction continue
						$Delimiter = '|^|'
						$GroupString = $DGroup.SamAccountName+$Delimiter+$DGroup.SID
                        if($GroupMembers -eq $null)
                        {
                            $Member = $GroupString+$Delimiter+$Delimiter
							$Member | Out-File -FilePath $Path -Force -Append
							Continue
                        }
						foreach ($GroupMember in $GroupMembers) 
						{ 
							Try{
								$Member = $GroupString+$Delimiter+$GroupMember.Name+$Delimiter+$GroupMember.SID 
								$GroupMembersObj += $Member
							}
							Catch{
								$swExceptionLog.WriteLine('Error - Issue with the Group Member listing')
								$swExceptionLog.WriteLine($GroupMember)
								$swExceptionLog.WriteLine($Error[0])
							}
						}
						$VerbosePreference = 'Continue'
						#region Writeout 
						#write content to GroupMembers with SreamWriter
						Try
						{
							# Create StreamWriter
							$SW = New-Object System.IO.StreamWriter($Path, $true, [System.Text.Encoding]::Unicode)
							# Parse through dataset and write out to actt log file
							Foreach ($Result in $GroupMembersObj)
							{
								$SW.WriteLine($Result)
							}
						}
						Catch
						{
							#Some error occurred attempting to write the extract .actt file. Writing error $errorlist
							$swExceptionLog.WriteLine("Error - Writing Export .actt File $Path")
							$swExceptionLog.WriteLine($Error[0])
						}
						Finally
						{
							$SW.close()
						}
						#endregion Writeout
				}
				Catch{
					#Code to extract Group Information using ADSI-LDAP in case of different domain groups
					$swExceptionLog.WriteLine('Error - Issue with the Group Listing')
					$swExceptionLog.WriteLine($DGroup)
					$swExceptionLog.WriteLine($Error[0])
					$MembersOfDiffDomain =  Get-ADGroup -Identity $DGroup -Properties Member | Select -ExpandProperty Member
						Foreach($Member in $MembersOfDiffDomain)
						{
							trap [Exception] 
							{
								$swExceptionLog.WriteLine('Error - Trapped Exception for Below Group and Member')
								$swExceptionLog.WriteLine($DGroup)
								$swExceptionLog.WriteLine($Member)
								$swExceptionLog.WriteLine($_.Exception.Message)
								continue
							}
								$Delimiter = '|^|'
								$ObjectS = [ADSI]"LDAP://$Member"
                                $objectSID =  (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $($ObjectS.objectsid), 0).value 
                                $MemberString = $DGroup.SamAccountName +$Delimiter+$DGroup.SID+$Delimiter+$ObjectS.sAMAccountName+$Delimiter+$objectSID.ToString()
							    $MemberString | Out-File -FilePath $Path -Force -Append
						}    
						continue
				}
            }
      		Write-ACTTDataLog -Message 'Exporting All Domain Groupmembers - groupmembers.actt'
			Write-host 'Exporting All Domain Group members - groupmembers.actt'
        }
		catch{
            #Some error occurred attempting to List all Domain Groups with requested attributes. Writing error $errorlist
			$swExceptionLog.WriteLine('Error - Could not list all Domain Group Members. Function name Get-DomainGroupsMembersAll')
			$swExceptionLog.WriteLine($Error[0])
		}

}




Function Get-DomainSensitiveGroupMembersAll
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all members in sensitive Domain Groups - groupmembers2.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all members in sensitive Domain Groups - groupmembers2.actt'
		<#
		File: groupmembers2.actt
		Report Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'
		#>
		Write-Host 'Searching Sensitive Domain Group Members'
		$SensitiveDomainGroupList = 'Domain Admins', 'Group Policy Creator Owners', 'Administrators', 'Enterprise Admins', 'Schema Admins', 'Account Operators', 'Server Operators', 'DnsAdmins'
		$colSensitiveDomainGroups = @()
		
		Foreach ($Group in $SensitiveDomainGroupList)
		{
			Try
			{
					# Get Group object
				$Filter = 'Name -eq ' + '"' + $Group + '"'
				$ADGroup = Get-ADGroup -Server $Server -Filter $Filter
				If ($null -eq $ADGroup -and $Group -eq 'Enterprise Admins' -or $Group -eq 'Schema Admins')
					{
						Write-ACTTDataLog -Message "Skipping Forest Level Sensitive Group - $Group in Child Domain $Server"
					}
				Else
				{
					#Get Group Members with Recursion
					$Members = Get-ADGroupMember -Identity $ADGroup -Recursive -ErrorAction Continue
				
					#Check for Empty $Members, if empty create the $objGroup psCustomObject with empty strings for member and objectSID
					if ($null -eq $Members)
					{
						$objGroup = [PSCustomObject] @{
						'GroupName' = $ADGroup.Name
						'GroupSID' = $ADGroup.SID
						'Member' = ''
						'objectSID' = ''
						}
						$colSensitiveDomainGroups += $objGroup
					}
					Else
					{
						#Else create a $objGroup for each member
						foreach ($Member in $Members)
						{
							Try
							{
							$objGroup = [PSCustomObject] @{
							'GroupName' = $ADGroup.Name
							'GroupSID' = $ADGroup.SID
							'Member' = $Member.Name
							'objectSID' = $Member.SID
								}
								$colSensitiveDomainGroups += $objGroup
							}
							Catch
							{
								$swExceptionLog.WriteLine('Error - Issue with member listing')
								$swExceptionLog.WriteLine($Member)
								$swExceptionLog.WriteLine($Error[0])
							}

						
						}
					}
				}
			}
			Catch
			{
				$swExceptionLog.WriteLine('Error - Issue with Group listing')
				$swExceptionLog.WriteLine($Group)
				$swExceptionLog.WriteLine($Error[0])
			}
		}
		
		Write-ACTTDataLog -Message 'Exporting Sensitive Domain Group Members - groupmembers2.actt'
		Write-host 'Exporting Sensitive Domain Group Members - groupmembers2.actt'
		Write-ActtFile -Data $colSensitiveDomainGroups -Path $(Join-Path $Path 'groupmembers2.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all sensitive Domain Groups Members with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Senstive Domain Groups Members')
		$swExceptionLog.WriteLine($Error[0])
	}
}



Function Get-DomainUsersAll
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Domain Users Accounts - users.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Domain Users Accounts - users.actt'
		Write-Host 'Exporting All Domain Users'
		
		$UserProps = @(
			'SamAccountName', 'DistinguishedName', 'ObjectSID',
			'Name', 'Description', 'pwdlastset',
			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'
			'CannotChangePassword', 'LockedOut', 'Enabled',
			'PasswordNeverExpires', 'PasswordNotRequired', 'AccountExpirationDate', 'LastLogonDate', 'whenchanged')
		
		$AllDomainUsers = Get-ADUser -Server $Server -Filter * -Properties $UserProps
		Write-ACTTDataLog -Message "Search Returned $($AllDomainUsers.Count) Users"
		Write-Host "Search Returned $($AllDomainUsers.Count) Users"
		$colUsers = @()
		$colUsers2 = @()
		
		foreach ($User in $AllDomainUsers)
		{
			#Build psCustomObject
			$objUser = [PSCustomObject] @{
				'ObjectSID' = $User.ObjectSID
				'SamAccountName' = $User.SamAccountName
				'Name' = $User.Name
				'Description' = $User.Description
				'Enabled' = $User.Enabled
				'pwdlastset' = $User.pwdlastset
				'useraccountcontrol' = $User.useraccountcontrol
				'whencreated' = $User.whencreated
				'Lockedout' = $User.LockedOut
				'PasswordNeverExpires' = $User.PasswordNeverExpires
				'PasswordNotRequired' = $User.PasswordNotRequired
				'CannotChangePassword' = $User.CannotChangePassword
				#'lastlogontimestamp' = $User.lastlogontimestamp
                'lastlogontimestamp' = IF($User.lastlogontimestamp -gt 535062067953226305) {'535062067953226305'} Else {[String]$User.lastlogontimestamp}
				'LastLogonDate' = $User.LastLogonDate
				'AccountExpirationDate' = $User.AccountExpirationDate
				'DistinguishedName' = $User.DistinguishedName
				'whenchanged' = $User.whenchanged
			}

			$objUser2 = [PSCustomObject] @{
        'SID' = $User.ObjectSID
        'FullName' = $User.Name
        'Name' = $User.SamAccountName
        'Description' = $User.Description
        'Disabled' = -not $User.Enabled
        'Lockout' = $User.LockedOut
        'PasswordExpires' = -not $User.PasswordNeverExpires
        'PasswordRequired' = -not $User.PasswordNotRequired
        'PasswordChangeable' = -not $User.CannotChangePassword
        'DistinguishedName' = $User.DistinguishedName
      }
			
			# Add psCustomObject to Collection
			$colUsers += $objUser
			$colUsers2 += $objUser2
		}
		
		Write-host 'Exporting All Domain Users - users.actt'
		Write-ACTTDataLog -Message 'Exporting All Domain Users - users.actt'
		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt')
		
		Write-host 'Exporting All Domain Users - users2.actt'
		Write-ACTTDataLog -Message 'Exporting All Domain Users - users2.actt'
		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users2.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Users')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-DomainUsersStatus
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Domain Users Accounts - users2.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Domain Users Accounts - users2.actt'
		Write-Host 'List All Domain Users2'
		
		$UserProps = @(
			'SamAccountName', 'DistinguishedName', 'ObjectSID',
			'Name', 'Description', 'pwdlastset',
			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'
			'CannotChangePassword', 'LockedOut', 'Enabled',
			'PasswordNeverExpires', 'PasswordNotRequired')
		
		$AllDomainUsers = Get-ADUser -Server $Server -Filter * -Properties $UserProps
		Write-ACTTDataLog -Message "Search Returned $($AllDomainUsers.Count) Users2"
		Write-Host "Search Returned $($AllDomainUsers.Count) Users2"
		
		$colUsers2 = @()
		
		foreach ($User in $AllDomainUsers)
		{
			#Build psCustomObject
			
			$objUser2 = [PSCustomObject] @{
        'SID' = $User.ObjectSID
        'FullName' = $User.Name
        'Name' = $User.SamAccountName
        'Description' = $User.Description
        'Disabled' = -not $User.Enabled
        'Lockout' = $User.LockedOut
        'PasswordExpires' = -not $User.PasswordNeverExpires
        'PasswordRequired' = -not $User.PasswordNotRequired
        'PasswordChangeable' = -not $User.CannotChangePassword
        'DistinguishedName' = $User.DistinguishedName
      }
			
			# Add psCustomObject to Collection
			
			$colUsers2 += $objUser2
		}
		
				
		Write-host 'Exporting All Domain Users - users2.actt'
		Write-ACTTDataLog -Message 'Exporting All Domain Users - users2.actt'
		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users2.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Users2')
		$swExceptionLog.WriteLine($Error[0])
	}
}

Function Get-DirectoryUsersAll
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Domain Users Accounts - users.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Domain Users Accounts - users.actt via DirectorySearcher'
		Write-host 'List all Domain Users Accounts- users.actt'
				
		$root = [ADSI]''
        $searcher = new-object System.DirectoryServices.DirectorySearcher($root)

		$searcher.filter = "(&(objectCategory=person)(objectClass=user))"
		
		$searcher.PropertiesToLoad.AddRange(@("SamAccountName","DistinguishedName","ObjectSID","Name","Description","pwdlastset","useraccountcontrol", "whencreated", "lastlogontimestamp", "whenchanged", "accountexpires"))
		$searcher.PageSize = 1000
		$USERLIST = $searcher.FindAll() 
				
		Write-ACTTDataLog -Message "Search Returned $($USERLIST.Count) Users"
		Write-Host "Search Returned $($USERLIST.Count) Users"
		$colUsers = @()
				
		foreach ($User in $USERLIST)
		{
			#Build psCustomObject
			$objUser = [PSCustomObject] @{
				'ObjectSID' = New-Object System.Security.Principal.SecurityIdentifier($User.properties.objectsid[0],0)
				'SamAccountName' = [string]$User.properties["samaccountname"]
				'Name' = [string]$User.properties["name"]
				'Description' = [string]$User.properties["description"]
				'pwdlastset' = [string]$User.properties["pwdlastset"]
				'useraccountcontrol' = [string]$User.properties["useraccountcontrol"]
				'whencreated' = [string]$User.properties["whencreated"]
				'lastlogontimestamp' = IF($User.properties["lastlogontimestamp"] -gt 535062067953226305) {'535062067953226305'} Else {[String]$User.properties["lastlogontimestamp"]}
				#'LastLogonDate' = [string]$User.properties.lastlogonDate
				'DistinguishedName' = [string]$User.properties["distinguishedname"]
				'whenchanged' = [string]$User.properties["whenchanged"]
				'AccountExpirationDate' = If(($User.Properties["accountexpires"] -le 0) -or ($User.Properties["accountexpires"] -gt 2650385917000000000)) {''} Else {[datetime]::fromfiletime([string]$User.Properties["accountexpires"])}			
				
			}
			# Add psCustomObject to Collection
			$colUsers += $objUser
						
      }			
				
		Write-host 'Exporting All Domain Users - users.actt'
		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt')
		Write-ACTTDataLog -Message 'Exporting All Domain Users - users.actt'
				
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Users')
		$swExceptionLog.WriteLine($Error[0])
	}
	
}




Function Get-DefDomainPwdPol
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	# Get Default Domain Password Policy - SecPol.actt
	Try
	{
		Write-ACTTDataLog -Message 'Get Default Domain Password Policies - SecPol.actt'
		$RootDSE = Get-ADRootDSE -Server $Server 
		$AccountPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Server -Identity $RootDSE.defaultNamingContext
		$colDefDomainPolicy = @()		
		$PolicyNeeded = @('ComplexityEnabled', 'LockoutDuration', 'lockOutObservationWindow', 'lockoutThreshold', 'MaxPasswordAge', 'MinPasswordAge', 'MinPasswordLength', 'PasswordHistoryCount', 'ReversibleEncryptionEnabled') 
		If($null -ne $AccountPolicy)
		{
			ForEach ($Policy in $PolicyNeeded)
			{
									
						#Build DomainControllerObject
				                $objSP = [PSCustomObject] @{
					            'SettingName'  = $Policy
					            'SettingValue' = $AccountPolicy.$Policy					            
				                }
				                $colDefDomainPolicy += $objSP                                               					
							

			}
		}
		else
		{
			ForEach ($item in $PolicyNeeded)
			{
				$objSP = [PSCustomObject] @{
					        'SettingName'    = $item
					        'SettingValue' = 'Not Defined'					        
				        }
				        # Add objSP to colSPNumeric
				        $colDefDomainPolicy += $objSP
			}
		}
		
		Write-ACTTDataLog -Message 'Exporting Default Domain Password Policies - SecPol.actt'
		Write-host 'Exporting Default Domain Password Policies - SecPol.actt'
		Write-ActtFile -Data $colDefDomainPolicy -Path $(Join-Path $Path 'SecPol.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Policies. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Default Domain Password Policies - SecPol.actt')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-FineGrainedPSO
{
	[CmdletBinding()]
	param (		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Domain PSOs Accounts - PSOs.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Domain PSOs Accounts - PSOs.actt via DirectorySearcher'
		Write-host 'List all Domain PSOs Accounts- PSOs.actt'
				
		$root = [ADSI]''
        $searcher = new-object System.DirectoryServices.DirectorySearcher($root)

		$searcher.filter = "(objectClass=msDS-PasswordSettings)"
		
		$searcher.PropertiesToLoad.AddRange(@("msds-lockoutduration","msds-minimumpasswordage","msds-lockoutobservationwindow","msds-maximumpasswordage","msds-lockoutthreshold","msds-passwordcomplexityenabled","msds-passwordhistorylength", "msds-minimumpasswordlength", "msds-psoappliesto", "whenchanged", "msds-passwordsettingsprecedence","cn"))
		$searcher.PageSize = 1000
		$PSOLIST = $searcher.FindAll() 
				
		Write-ACTTDataLog -Message "Search Returned $($PSOLIST.Count) PSOs"
		Write-Host "Search Returned $($PSOLIST.Count) PSOs"
		$colPSOs = @()
				
		foreach ($PSO in $PSOLIST)
		{
            #Caculation of timespan 
            $MaxPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-maximumpasswordage')" 
            $ObservationWindow  = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutobservationwindow')" 
            $MinPwdAge          = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-minimumpasswordage')" 
            $LockOutDuration    = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutduration')" 
			#Build psCustomObject
            
            TRY
            {
               If($PSO.properties.'msds-psoappliesto' -eq $null)
               {
               EXCEPTION
               }
            }
            catch{
            $objUser = [PSCustomObject] @{
					'PSOName'       = "$($PSO.properties.'cn')" 
					'AppliesTo'     = "N/A - Not applied to any user/group"
					'ObjectType'     = "N/A"
					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
					'msds-minimumpasswordlength'               = $($PSO.properties.'msds-minimumpasswordlength') 
					'whenchanged'                              = $($PSO.properties.whenchanged) 
				}
                $colPSOs += $objUser
            Continue
            }

			foreach($dnApp in $PSO.properties.'msds-psoappliesto')
			{
				$ADObject=[ADSI]"LDAP://$dnApp" 
				$objUser = [PSCustomObject] @{
					'PSOName'       = "$($PSO.properties.'cn')" 
					'AppliesTo'     = "$($ADObject.Get('cn'))"
					'ObjectType'     = "$($ADObject.Get('objectclass'))"
					'msds-maximumpasswordage'                  = if($MaxPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MaxPwdAge} 
					'msds-passwordsettingsprecedence'          = $($PSO.properties.'msds-passwordsettingsprecedence') 
					'msds-lockoutthreshold'                    = $($PSO.properties.'msds-lockoutthreshold') 
					'msds-passwordcomplexityenabled'           = $($PSO.properties.'msds-passwordcomplexityenabled') 
					'msds-passwordhistorylength'               = $($PSO.properties.'msds-passwordhistorylength') 
					'msds-lockoutobservationwindow'            = if($ObservationWindow -eq '-10675199.02:48:05.4775808'){"Never"}else{$ObservationWindow} 
					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled') 
					'msds-minimumpasswordage'                  = if($MinPwdAge -eq '-10675199.02:48:05.4775808'){"Never"}else{$MinPwdAge} 
					'msds-lockoutduration'                     = if($LockOutDuration -eq '-10675199.02:48:05.4775808'){"Never"}else{$LockOutDuration} 
					'msds-minimumpasswordlength'               = $($PSO.properties.'msds-minimumpasswordlength') 
					'whenchanged'                              = $($PSO.properties.whenchanged) 
				}
				# Add psCustomObject to Collection
			$colPSOs += $objUser

			}
            

      }			
				
		Write-host 'Exporting All Domain PSOs - PSOs.actt'
		Write-ActtFile -Data $colPSOs -Path $(Join-Path $Path 'PSOs.actt')
		Write-ACTTDataLog -Message 'Exporting All Domain PSOs - PSOs.actt'
				
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain PSOs Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain PSOs')
		$swExceptionLog.WriteLine($Error[0])
	}
	
}




Function Get-DomainPwdPol
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	# Get Domain pwdPolicies - domainpolicy.actt
	Try
	{
		Write-ACTTDataLog -Message 'Get Domain pwdPolicies - domainpolicy.actt'
		$RootDSE = Get-ADRootDSE -Server $Server 
		$AccountPolicy = Get-ADObject -Identity $RootDSE.defaultNamingContext -Server $Server -Property *
		$colDomainPolicy = @()
		
		If ($AccountPolicy.pwdProperties -band 0x4)
		{
			#Writing to Data Log
			Write-ACTTDataLog -Message 'Prevent Transfer of Passwords in Clear Text|^|Enabled'
			$objDomainPolicy = [PSCustomObject] @{
				'Parameter' = 'Prevent Transfer of Passwords in Clear Text'
				'Value' = 'Enabled'
			}
			$colDomainPolicy += $objDomainPolicy
		}
		Else
		{
			#'Writing to Data Log
			Write-ACTTDataLog -Message 'Prevent Transfer of Passwords in Clear Text|^|Disabled'
			$objDomainPolicy = [PSCustomObject] @{
				'Parameter' = 'Prevent Transfer of Passwords in Clear Text'
				'Value' = 'Disabled'
			}
			$colDomainPolicy += $objDomainPolicy
		}
		
		If ($AccountPolicy.pwdProperties -band 0x8)
		{
			#Writing to Data Log
			Write-ACTTDataLog -Message 'Allow Lockout of Administrator Account|^|Enabled'
			$objDomainPolicy = [PSCustomObject] @{
				'Parameter' = 'Allow Lockout of Administrator Account'
				'Value' = 'Enabled'
			}
			$colDomainPolicy += $objDomainPolicy
		}
		Else
		{
			#Writing to Data Log
			Write-ACTTDataLog -Message 'Allow Lockout of Administrator Account|^|Disabled'
			$objDomainPolicy = [PSCustomObject] @{
				'Parameter' = 'Allow Lockout of Administrator Account'
				'Value' = 'Disabled'
			}
			$colDomainPolicy += $objDomainPolicy
		}
		
		Write-ACTTDataLog -Message 'Exporting Domain pwdPolicies - domainpolicy.actt'
		Write-host 'Exporting Domain pwdPolicies - domainpolicy.actt'
		Write-ActtFile -Data $colDomainPolicy -Path $(Join-Path $Path 'domainpolicy.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Policies. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Policies')
		$swExceptionLog.WriteLine($Error[0])
	}
}

Function Get-DomainSecPol
{
	
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	
	Try
	{
		Write-ACTTDataLog -Message 'Get Domain Security Policies - Numeric - securitypolicynumeric.actt'
		
		$objWMIQuery = Get-WmiObject -Namespace root\rsop\computer -Query 'SELECT KeyName, Precedence, Setting FROM RSOP_SecuritySettingNumeric' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$colSPNumeric = @()
		$securitypolicynumeric = @('MaximumPasswordAge', 'LockoutBadCount', 'MinimumPasswordLength', 'ResetLockoutCount', 'LockoutDuration', 'PasswordHistorySize', 'MinimumPasswordAge')
		$notDefinedvalue = $null
		If ($null -ne $objWMIQuery)
		{
            foreach ($Policy in $securitypolicynumeric)
            {
                    $notDefinedvalue = $Policy
                    ForEach ($item in $objWMIQuery)
			        {                          
                        If($Policy -eq $item.KeyName)
                        {
                             #Build DomainControllerObject
				                $objSP = [PSCustomObject] @{
					            'KeyName'    = $item.KeyName
					            'Precedence' = $item.Precedence
					            'Setting'    = $item.Setting
				                }
				                $colSPNumeric += $objSP
                            
                            $notDefinedvalue = $null

                        }
						
                		
			        }
                    
                    if ($null -ne $notDefinedvalue)
                    {
                        $objSP = [PSCustomObject] @{
					        'KeyName'    = $notDefinedvalue
					        'Precedence' = 'Not Defined'
					        'Setting'    = 'Not Defined'
				        }
				        # Add objSP to colSPNumeric
				        $colSPNumeric += $objSP
                    }

            }                   

		}
		
		else
		{
			ForEach ($Policy in $securitypolicynumeric)
			{
				$objSP = [PSCustomObject] @{
					'KeyName'    = $Policy
					'Precedence' = 'Not Defined'
					'Setting'    = 'Not Defined'
				}
				# Add objSP to colSPNumeric
				$colSPNumeric += $objSP
			}
		}
		
		Write-ACTTDataLog -Message 'Exporting Domain Security Policies - Numeric - securitypolicynumeric.actt'
		Write-host 'Exporting Domain Security Policies - Numeric - securitypolicynumeric.actt'
		Write-ActtFile -Data $colSPNumeric -Path $(Join-Path $Path 'securitypolicynumeric.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Security Policies - Numeric. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Security Policies - Numeric')
		$swExceptionLog.WriteLine($WMIError[0])
	}
}

Function Get-DomainSecPolBoolean
{
	
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	
	Try
	{
		Write-ACTTDataLog -Message 'Get Domain Security Policies - Boolean - securitypolicyboolean.actt'
		
		$objWMIQuery = Get-WmiObject -Namespace root\rsop\computer -Query 'SELECT KeyName, Precedence, Setting FROM RSOP_SecuritySettingBoolean' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$colSPBoolean = @()
		$securityBoolList = @('ClearTextPassword', 'ForceLogoffWhenHourExpire', 'PasswordComplexity', 'RequireLogonToChangePassword')
		$notDefinedvalue = $null
		If ($null -ne $objWMIQuery)
		{
            foreach ($Policy in $securityBoolList)
            {
                    $notDefinedvalue = $Policy
                    ForEach ($item in $objWMIQuery)
			        {                          
                        If($Policy -eq $item.KeyName)
                        {
                             
				                $objSP = [PSCustomObject] @{
					            'KeyName'    = $item.KeyName
					            'Precedence' = $item.Precedence
					            'Setting'    = $item.Setting
				                }
				                $colSPBoolean += $objSP
                            
                            $notDefinedvalue = $null

                        }
						
                		
			        }
                    
                    if ($null -ne $notDefinedvalue)
                    {
                        $objSP = [PSCustomObject] @{
					        'KeyName'    = $notDefinedvalue
					        'Precedence' = 'Not Defined'
					        'Setting'    = 'Not Defined'
				        }
				        # Add objSP to colSPNumeric
				        $colSPBoolean += $objSP
                    }

            }                   

		}
		else
		{
			ForEach ($Policy in $securityBoolList)
			{
				$objSP = [PSCustomObject] @{
					'KeyName'    = $Policy
					'Precedence' = 'Not Defined'
					'Setting'    = 'Not Defined'
				}
				# Add objSP to colSPBoolean
				$colSPBoolean += $objSP
			}
		}
		
		Write-ACTTDataLog -Message 'Exporting Domain Security Policies - Boolean - securitypolicyboolean.actt'
		Write-host 'Exporting Domain Security Policies - Boolean - securitypolicyboolean.actt'
		Write-ActtFile -Data $colSPBoolean -Path $(Join-Path $Path 'securitypolicyboolean.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Domain Security Policies - Boolean. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Security Policies - Boolean')
		$swExceptionLog.WriteLine($Error[0])
	}
}


#region LocalServerFunctions
Function Get-LocalGroupsAll
{
	<#
	.SYNOPSIS
		List all Local Groups - groups.actt
	
	.DESCRIPTION
		

	.PARAMETER  Server
		

	.EXAMPLE
	

	.PARAMETER  Credential
		

	.EXAMPLE
		

	.INPUTS
		

	.OUTPUTS
		groups.actt

	.NOTES
		

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Local Groups - groups.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Local Groups - groups.actt'
	<#
        File: groups.actt
        Report Fields: 'GroupName', 'GroupSID', 'Description'
    #>
		Write-Host 'Searching All Local Groups'
		$AllDEntry = [ADSI]"WinNT://$Server"
		$colGroups = @()
		
		foreach ($GroupEntry in $AllDEntry.Children | where { $_.SchemaClassName -eq 'group' })
		{
			foreach ($Group in $GroupEntry[0] | select *)
			{
				try
				{
					$objUser = [PSCustomObject] @{
						'objectsid'	 	= (New-Object System.Security.Principal.SecurityIdentifier($Group.objectSid.value, 0)).Value
						'GroupName'   	= $Group.Name
						'Description'	= $Group.Description
												
					}
				}
				catch
				{
					$swExceptionLog.WriteLine($Error[0])
					continue
				}
				
			}
			$colGroups += $objUser
		}
		
		Write-ACTTDataLog -Message 'Exporting All Local Groups - groups.actt'
		Write-host 'Exporting All Local Groups - groups.actt'
		Write-ActtFile -Data $colGroups -Path $(Join-Path $Path 'groups.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Local Groups with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Local Groups')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-LocalGroupsMembersAll
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all members in Local Groups - groupmembers.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Local Group Members - groupmembers.actt'
	<#
        File: groupmembers.actt
        Report Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'
    #>
		Write-Host 'Searching All Local Group Members'
		$AllDEntry = [ADSI]"WinNT://$Server"
		$colLocalGroupsMembers = @()
		#Check for Empty $Members, if empty create the $objGroup psCustomObject
		foreach ($Group in $AllDEntry.Children | where { $_.SchemaClassName -eq 'group' })
		{
			Foreach($groupdetail in $Group[0] | select *)
			{
				try
				{
					$objGroup = [PSCustomObject] @{
						'GroupName' = $groupdetail.Name
						'GroupSID'  = (New-Object System.Security.Principal.SecurityIdentifier($groupdetail.objectSid.value, 0)).Value
						'Member'    = ''
						'objectSid' = ''
						
					}
					$colLocalGroupsMembers += $objGroup
										
				}
				Catch
				{
					$swExceptionLog.WriteLine($Error[0])
					continue
				}
				
				
			}
			
			Foreach ($Groupmember in $AllDEntry.psbase.children.find($Group.Name, 'Group'))
			{
				Try
				{
					Foreach ($Member in $Groupmember.psbase.invoke("members"))
					{
						#$MemberDetails = new DirectoryEntry($Member)
						try
						{
							$objGroup = [PSCustomObject] @{
								'GroupName' = $Group.Name
								'GroupSID'  = (New-Object System.Security.Principal.SecurityIdentifier($Group.objectSid.value, 0)).Value
								'Member'    = $Member.GetType().InvokeMember("Name", 'GetProperty', $null, $Member, $null)
								'objectSid' = (New-Object System.Security.Principal.SecurityIdentifier($Member.GetType().InvokeMember("objectSid", 'GetProperty', $null, $Member, $null), 0)).Value 
							
							}
							$colLocalGroupsMembers += $objGroup
						}
						catch
						{
							$swExceptionLog.WriteLine($Error[0])
							continue
						}
					}
				}
				Catch
				{
					$swExceptionLog.WriteLine('Error - With the below GroupMember')
					$swExceptionLog.WriteLine($Member)
					$swExceptionLog.WriteLine($Error[0])
					continue
				}
				
				
			}
			
		}
		
		
		
		Write-ACTTDataLog -Message 'Exporting All Local Groupmembers - groupmembers.actt'
		Write-host 'Exporting All Local Group members - groupmembers.actt'
		Write-ActtFile -Data $colLocalGroupsMembers -Path $(Join-Path $Path 'groupmembers.actt')
	}
	
	Catch
	{
		#Some error occurred attempting to List all Local Groups with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all local Group Members')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Convert-UserFlag
{
	
	Param ($UserFlag)
	
	$List = New-Object  System.Collections.ArrayList
	
	Switch ($UserFlag)
	{
		
		($UserFlag -BOR 0x0001) { [void]$List.Add('SCRIPT') }
		
		($UserFlag -BOR 0x0002) { [void]$List.Add('ACCOUNTDISABLE') }
		
		($UserFlag -BOR 0x0008) { [void]$List.Add('HOMEDIR_REQUIRED') }
		
		($UserFlag -BOR 0x0010) { [void]$List.Add('LOCKOUT') }
		
		($UserFlag -BOR 0x0020) { [void]$List.Add('PASSWD_NOTREQD') }
		
		($UserFlag -BOR 0x0040) { [void]$List.Add('PASSWD_CANT_CHANGE') }
		
		($UserFlag -BOR 0x0080) { [void]$List.Add('ENCRYPTED_TEXT_PWD_ALLOWED') }
		
		($UserFlag -BOR 0x0100) { [void]$List.Add('TEMP_DUPLICATE_ACCOUNT') }
		
		($UserFlag -BOR 0x0200) { [void]$List.Add('NORMAL_ACCOUNT') }
		
		($UserFlag -BOR 0x0800) { [void]$List.Add('INTERDOMAIN_TRUST_ACCOUNT') }
		
		($UserFlag -BOR 0x1000) { [void]$List.Add('WORKSTATION_TRUST_ACCOUNT') }
		
		($UserFlag -BOR 0x2000) { [void]$List.Add('SERVER_TRUST_ACCOUNT') }
		
		($UserFlag -BOR 0x10000) { [void]$List.Add('DONT_EXPIRE_PASSWORD') }
		
		($UserFlag -BOR 0x20000) { [void]$List.Add('MNS_LOGON_ACCOUNT') }
		
		($UserFlag -BOR 0x40000) { [void]$List.Add('SMARTCARD_REQUIRED') }
		
		($UserFlag -BOR 0x80000) { [void]$List.Add('TRUSTED_FOR_DELEGATION') }
		
		($UserFlag -BOR 0x100000) { [void]$List.Add('NOT_DELEGATED') }
		
		($UserFlag -BOR 0x200000) { [void]$List.Add('USE_DES_KEY_ONLY') }
		
		($UserFlag -BOR 0x400000) { [void]$List.Add('DONT_REQ_PREAUTH') }
		
		($UserFlag -BOR 0x800000) { [void]$List.Add('PASSWORD_EXPIRED') }
		
		($UserFlag -BOR 0x1000000) { [void]$List.Add('TRUSTED_TO_AUTH_FOR_DELEGATION') }
		
		($UserFlag -BOR 0x04000000) { [void]$List.Add('PARTIAL_SECRETS_ACCOUNT') }
		
	}
	
	$List -join ', '
	
}


Function Get-LocalUsersAll
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Local Users Accounts - users.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Local Users Accounts - users.actt'
		Write-Host 'List All Local Users'
		
		
		#$UserProps = @('objectsid', 'lastlogin', 'name', 'description', 'passwordage', 'useraccountcontrol', 'whencreated', 'lastlogontimestamp')
		
		$AllDEntry = [ADSI]"WinNT://$Server"
		
		#Write-ACTTDataLog -Message "Search Returned $($AllDEntry.Count) Users"
		#Write-Host "Search Returned $($AllDEntry.Count) Users"
		$colUsers = @()
		$colUsers2 = @()
		
		foreach ($UserEntry in $AllDEntry.Children | where { $_.SchemaClassName -eq 'user' })
		{
			try
			{
				foreach ($User in $UserEntry[0] | select *)
			{
				try
				{
					$objUser = [PSCustomObject] @{
						'objectsid'		     = (New-Object System.Security.Principal.SecurityIdentifier($User.objectSid.value, 0)).Value
						'Name'			     = $User.Name
						'FullName'		     = $User.FullName
#						'Username'		     = $User.Username
						'Description'	     = $User.Description
						'lastlogin'		     = If ($User.LastLogin[0] -is [datetime]) { $User.LastLogin[0] } Else { 'Never logged  on' }
						'passwordage'	     = [math]::Round($User.PasswordAge[0]/86400)
						'useraccountcontrol' = $User.userflags
						'ACCOUNTDISABLE' = Switch ($User.userflags[0]) { ($User.userflags[0] -BOR 0x0002) { 'True' }
							default { 'False' }
						}
						'PASSWD_CANT_CHANGE' = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0040) { 'True' }
							default { 'False' }
						}
						'LOCKOUT' 			 = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0010) { 'True' }
							default { 'False' }
						}
						'PASSWD_NOTREQD'	 = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0020) { 'True' }
							default { 'False' }
						}
						'DONT_EXPIRE_PASSWORD' = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0020) { 'True' }
							default { 'False' }
						}
						'PasswordExpired'    = $User.PasswordExpired
						
					}
					$colUsers += $objUser

					
				}
				catch
				{
					$swExceptionLog.WriteLine('Error - Issue identified for one of the Local Users')
					$swExceptionLog.WriteLine($User)
					$objUser = [PSCustomObject] @{
						'objectsid'		     = (New-Object System.Security.Principal.SecurityIdentifier($User.objectSid.value, 0)).Value
						'Name'			     = $User.Name
						'FullName'		     = $User.FullName
#						'Username'		     = $User.Username
						'Description'	     = $User.Description
						'lastlogin'		     = ''
						'passwordage'	     = [math]::Round($User.PasswordAge[0]/86400)
						'useraccountcontrol' = $User.userflags
						'ACCOUNTDISABLE' = Switch ($User.userflags[0]) { ($User.userflags[0] -BOR 0x0002) { 'True' }
							default { 'False' }
						}
						'PASSWD_CANT_CHANGE' = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0040) { 'True' }
							default { 'False' }
						}
						'LOCKOUT' 			 = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0010) { 'True' }
							default { 'False' }
						}
						'PASSWD_NOTREQD'	 = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0020) { 'True' }
							default { 'False' }
						}
						'DONT_EXPIRE_PASSWORD' = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0020) { 'True' }
							default { 'False' }
						}
						'PasswordExpired'    = $User.PasswordExpired
						
					}
					$colUsers += $objUser
					$swExceptionLog.WriteLine($Error[0])
					continue
				}
				
			}
			}
			Catch
			{
				$swExceptionLog.WriteLine('Error - Issue identified for one of the Local UserEntry Object')
				$swExceptionLog.WriteLine($UserEntry)
				$swExceptionLog.WriteLine($Error[0])
				continue
			}
			
			
		}

		foreach ($UserEntry in $AllDEntry.Children | where { $_.SchemaClassName -eq 'user' })
		{
			Try
			{
				foreach ($User in $UserEntry[0] | select *)
			{
				try
				{
					$objUser2 = [PSCustomObject] @{
						'SID'		     = (New-Object System.Security.Principal.SecurityIdentifier($User.objectSid.value, 0)).Value
						'Name'			     = $User.Name
						'FullName'		     = $User.FullName
						'Description'	     = $User.Description
						'useraccountcontrol' = $User.userflags
						'Disabled' = Switch ($User.userflags[0]) { ($User.userflags[0] -BOR 0x0002) { 'True' }
							default { 'False' }
						}
						'PasswordChangeable' = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0040) { 'False' }
							default { 'True' }
						}
						'LOCKOUT' 			 = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0010) { 'True' }
							default { 'False' }
						}
						'PasswordRequired'	 = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0020) { 'False' }
							default { 'True' }
						}
						'PasswordExpires' = Switch ($User.userflags[0])
						{
							($User.userflags[0] -BOR 0x0020) { 'False' }
							default { 'True' }
						}
						
						
					}
														
					$colUsers2 += $objUser2
										
				}
				catch
				{
					$swExceptionLog.WriteLine('Error - Issue identified for one of the Local Users in USERS3')
					$swExceptionLog.WriteLine($User)
					$swExceptionLog.WriteLine($Error[0])
				}
				
			}
			}
			Catch
			{
				$swExceptionLog.WriteLine('Error - Issue identified for one of the Local UserEntry Object in Users3')
				$swExceptionLog.WriteLine($UserEntry)
				$swExceptionLog.WriteLine($Error[0])
				continue
			}
			
			
		}
		
		
		Write-ACTTDataLog -Message 'Exporting All Local Users - users.actt'
		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt')
		Write-host 'Exporting All Local Users - users.actt'
		
		Write-ACTTDataLog -Message 'Exporting All Local Users - users3.actt'
		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users3.actt')
		Write-host 'Exporting All Local Users - users3.actt'
	}
	
	Catch
	{
		#Some error occurred attempting to List all Local Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Local Users')
		$swExceptionLog.WriteLine($Error[0])
	}
}




Function Get-LocalWMIUsersAll
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $false)]
		[String]$Server,		
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	#List all Local Users Accounts - users.actt
	Try
	{
		Write-ACTTDataLog -Message 'List all Local Users Accounts - users.actt'
		Write-Host 'Exporting All Local Users'
		#$now = Get-Date
#		$UserProps = @(
#			'SamAccountName', 'ObjectSID',
#			'Name', 'Description', 'pwdlastset',
#			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'
#			'CannotChangePassword', 'LockedOut', 'Enabled',
#			'PasswordNeverExpires', 'PasswordNotRequired')
		
		$AllLocalUsers = Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" -ComputerName $Server -ErrorAction Stop
		Write-ACTTDataLog -Message "Search Returned $($AllLocalUsers.Count) Users"
		Write-Host "Search Returned $($AllLocalUsers.Count) Users"
		$colUsers = @()
		
		
		foreach ($User in $AllLocalUsers)
		{
			try
			{
				#Build psCustomObject
				$objUser = [PSCustomObject] @{
					'SID'		       = $User.SID
					'Name'	   = $User.Name
					'FullName'		   = $User.FullName
					'Description'		   = $User.Description
					'Disabled'			   = $User.Disabled
					#'useraccountcontrol'   = $User.useraccountcontrol
					#'whencreated'		   = $User.whencreated
					'Lockout'		       = $User.LockOut
					'PasswordExpires' = $User.PasswordExpires
					'PasswordRequired'  = $User.PasswordRequired
					'PasswordChangeable' = $User.PasswordChangeable
					#'lastlogontimestamp'   = $User.LastLogin
					
				}
				
				
				# Add psCustomObject to Collection
				$colUsers += $objUser
				
			}
			Catch
			{
				$swExceptionLog.WriteLine('Error - Could not list this Local Users2')
				$swExceptionLog.WriteLine($Error[0])
				continue
			}
			
		}
		
		
		Write-ACTTDataLog -Message 'Exporting All Local Users - users2.actt'
		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users2.actt')
		Write-host 'Exporting All Local Users - users2.actt'
	}
	
	Catch
	{
		#Some error occurred attempting to List all Local Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Local Users2')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-LocalPwdPol
{
	[CmdletBinding()]
	param (
		[Parameter(
				   Mandatory = $true)]
		[Object]$Path)
	
	# Get Local pwdPolicies - LocalSecuritypolicy.txt
	Try
	{
		Write-Host 'Exporting Local pwdPolicies - LocalSecuritypolicy.txt'
		Write-ACTTDataLog -Message 'Get Local pwdPolicies - LocalSecuritypolicy.txt'
		SecEdit /export /cfg $(Join-Path $Path 'LocalSecuritypolicy.txt') /areas SecurityPolicy
		Write-ACTTDataLog -Message 'Exporting Local pwdPolicies - LocalSecuritypolicy.txt'
 		$LocalPwdValues = Import-Csv -Path $(Join-Path $Path 'LocalSecuritypolicy.txt') -Delimiter '=' -Header 'Property','Value'
        $colDefLocalPolicy = @()		
		$PolicyNeeded = @('MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration', 'ClearTextPassword')
        If($null -ne $LocalPwdValues)
        {          
        	ForEach($Policy in $PolicyNeeded){
                                
				                #Build DomainControllerObject
				                $objSP = [PSCustomObject] @{
					            'SettingName'  = $Policy	
                                'SettingValue' = if($null -ne $($LocalPwdValues |Where-Object {$_.Property -like $($Policy+'*')} |Select-Object -Expand Value)) {$LocalPwdValues |Where-Object {$_.Property -like $($Policy+'*')} |Select-Object -Expand Value } ELSE {'Not Defined' }
								}            
                                          
                                $colDefLocalPolicy += $objSP
                                }                
         }
		Else
		{			
           ForEach($Policy in $PolicyNeeded)
			{
				#Build DomainControllerObject
				                $objSP = [PSCustomObject] @{
					            'SettingName'  = $Policy
					            'SettingValue' = 'Not Defined'					            
				                }
				                $colDefLocalPolicy += $objSP        
			}
	     }
		Write-host 'Exporting Local pwdPolicies - LocalSecuritypolicy.actt'
		Write-ActtFile -Data $colDefLocalPolicy -Path $(Join-Path $Path 'secpol.actt')
				
	}
	
	Catch
	{
		#Some error occurred attempting to List all Local Policies. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not extract Policy via secedit')
		$swExceptionLog.WriteLine($Error[0])
	}
}



Function Get-LocalDomainGroups{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$Server,
        [Parameter(Mandatory = $true)]
        [Object]$Path)

        #List all nested groups in local Groups
     Try{

        Write-ACTTDataLog -Message 'List all Local Group Members - LocalDomaingroups'
   		Write-Host 'Searching for All Domain Groups'
		$AllDEntry = [ADSI]"WinNT://$Server"
		$colLocalDomainGroupMembers  = @()
        #Loop to get only Groups
        Foreach ($Group in $AllDEntry.Children | where { $_.SchemaClassName -eq 'group'}){
            #Loop to get nested groups
            Foreach ($Member in $Group.psbase.invoke("members") | where{$_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null) -eq 'group'}){
                Try{
                    #Check for Empty $Members, if empty create the $objGroup psCustomObject
                    if($null -eq $Member){
                        $objGroup = [PSCustomObject] @{
                        'GroupName' = $Group.Name
                        'GroupSID' = (New-Object System.Security.Principal.SecurityIdentifier($Group.objectSid.value,0)).value
                        'Member' = ''
                        'objectSID' = ''
                         }
                     $colLocalDomainGroupMembers += $objGroup
                     }
                     Else{
                        $objGroup = [PSCustomObject] @{
                        'GroupName' = $Group.GetType().InvokeMember("Name",'GetProperty',$null,$Group,$null)
                        'GroupSID' =  (New-Object System.Security.Principal.SecurityIdentifier($Group.objectSid.value,0)).value
                        'Member' = $Member.GetType().InvokeMember("Name",'GetProperty',$null,$Member,$null)
                        'objectSID' = (New-Object System.Security.Principal.SecurityIdentifier($Member.GetType().InvokeMember("objectSid",'GetProperty',$null,$Member,$null),0)).value
                         }
                     $colLocalDomainGroupMembers += $objGroup
                     }
                 }
                 Catch{
                    $swExceptionLog.WriteLine('Error - with the below Domain GroupMember')
                    $swExceptionLog.WriteLine($Member)
                    $swExceptionLog.WriteLine($Error[0])
                    continue
                 }
             }
        }
    }
    Catch{
        #Error occurred attempting to List Nested Groups
        $swExceptionLog.WriteLine('Error - Could not list nested domain groups')
        $swExceptionLog.WriteLine($Error[0])
    }

$colLocalDomainGroupMembers = $colLocalDomainGroupMembers | Sort-Object Member -Unique

Get-LocalDomainGroupMembersAll -LocalDomainGroups $colLocalDomainGroupMembers -DomainFQDN (Get-WmiObject win32_computersystem).Domain -Path $Path
}



Function Get-LocalDomainGroupMembersAll
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Object]$LocalDomainGroups,
        [Parameter(Mandatory = $true)]
        [String]$DomainFQDN,
        [Parameter(Mandatory = $true)]
        [String]$Path)
      
    #List all nested domain group members in localserver - localdomaingroupmembers.actt
    Try{
        Write-ACTTDataLog -Message 'List all members in Domain Groups - localdomaingroupmembers.actt'
        <#
        File: localdomaingroupmembers.actt
        Report Fields: 'GroupName', 'GroupSID' , 'Member' , 'ObjectSID' , 'ObjectType'
        #>
        Write-Host 'Searching for Domain Group Members'
        $colLocalDomainGroupMember = @()

        Foreach($Group in $LocalDomainGroups){
            Try{ 
                $LDAPString = "LDAP://<SID="+$Group.objectSID+">"
                $GroupProp = [adsi]$LDAPString              
                if($null -eq $GroupProp.Member){
                    $objGroupMem = [PSCustomObject] @{
                        'GroupName' = $Group.Member
                        'GroupSID'  = $Group.objectSID
                        'Member'    = ''
                        'objectSID' = ''
                        'objectType'= ''
                        }
                        $colLocalDomainGroupMember += $objGroupMem
                    }
                    Else{          
                        #Else create a $objGroupMem for each member
                        Foreach($Member in $GroupProp.Member){
                            Try{
                                $MemberProp = [ADSI]"LDAP://$Member"
                                $objGroupMem = [PSCustomObject] @{
                                'GroupName' = $Group.Member
                                'GroupSID' = $Group.ObjectSID
                                'Member' = $MemberProp.Name
                                'objectSID' = (New-Object System.Security.Principal.SecurityIdentifier $($MemberProp.objectsid),0).value
                                'objectType' = $MemberProp.objectClass
                                }
                                $colLocalDomainGroupMember += $objGroupMem
                            }
                            Catch{
                                $swExceptionLog.WriteLine('Error - Issue wth domain group member listing')
                                $swExceptionLog.WriteLine($Member)
                                $swExceptionLog.WriteLine($Error[0])
                            }
                         }
                    }
            }
            Catch{
                $swExceptionLog.WriteLine('Error - Issue with Domain Group Listing')
                $swExceptionLog.WriteLine($Group)
                $swExceptionLog.WriteLine($Error[0])
            }
        }

        Write-ActtDataLog -Message 'Exporting Domain Group Members - localdomaingroupmembers.actt'
        Write-Host 'Exporting Domain Group Members - localdomaingroupmembers.actt'
        Write-ActtFile -Data $colLocalDomainGroupMember -Path $(Join-Path $Path 'localdomaingroupmembers.actt')
        #$colLocalDomainGroupMember
    }
    Catch{
        $swExceptionLog.WriteLine('Error - Could not list all Domain Group Member')
        $swExceptionLog.WriteLine($Error[0])
    }
}





#endregion LocalServerFunctions



Function Get-ADData
{
# Writing to Data Log
Write-ACTTDataLog -Message 'Application Starts on DC....'

# Write ADAuditExtract_Version.ACTT
$swVersion = New-Object System.IO.StreamWriter($(Join-Path $Path 'ADAuditExtract_Version.actt'), $false, [System.Text.Encoding]::Unicode)
$swVersion.WriteLine('[Version] NVARCHAR(MAX)')
$swVersion.WriteLine($ScriptVersion)
$swVersion.Close()


# Check for Elevated Permissions
$RunningElevated = (whoami.exe /all | Select-String S-1-16-12288) -ne $null
# $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
# $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
# 	if($WindowsPrincipal.IsInRole("Domain Admins")) 
# 	{$RunningElevated = $True}    
#     else 
# 	{$RunningElevated = $false}	

If ($RunningElevated -eq $true)
{
	Write-ACTTDataLog -Message '--------Correct Privileges used to run the extractor.--------'
	Write-ACTTConfigSettings -Setting 'PowerShell Version' -Value $psVersion 
	Write-ACTTConfigSettings -Setting 'ExtractStartDateAndTime' -Value $ScriptStartTime
	# Get Host and User name currently logged in - HostandUserName.actt
	Get-HostAndUserDetails
	
	# Get EA Credentials for the AD Forest being audited
	#$Creds = Get-Credential #-Message "Please provide your Enterprise Admin/Domain Admin credentials for AD Forest $ForestFQDN"
    
    $swVersion = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_Platform_WindowsAD_ALL.ACTT'), $false, [System.Text.Encoding]::Unicode)
	$swVersion.WriteLine('[Version] NVARCHAR(MAX)')
	$swVersion.WriteLine($ScriptVersion)
	$swVersion.Close()	

	Write-ACTTDataLog -Message "Get EA Credentials for the AD Forest $ForestFQDN"
			
	$DomainBind = $ForestFQDN
	
	
	# Call all functions to query the AD Domain data
	
	Get-DomainComputersAll -Server $DomainBind -Path $Path
	Get-DomainGroupsAll -Server $DomainBind -Path $Path
	Get-DomainSensitiveGroupMembersAll -Server $DomainBind -Path $Path
	#Get-DomainUsersAll -Server $DomainBind -Path $Path
	Get-DirectoryUsersAll -Server $DomainBind -Path $Path
	Get-DomainUsersStatus -Server $DomainBind -Path $Path
	Get-DomainTrustsLatest -Server $DomainBind -Path $Path
	Get-DCsInDomain -Domain $DomainBind -Path $Path
	Get-DomainPwdPol -Server $ComputerName -Path $Path
	Get-DefDomainPwdPol -Server $ComputerName -Path $Path
	Get-DomainSecPol -Server $ComputerName -Path $Path
	Get-FineGrainedPSO -Path $Path
	Get-DomainSecPolBoolean -Server $DomainBind -Path $Path
	Get-GPOReportall -Server $ComputerName -Path $Path
	Get-ServerUserRights -Server $ComputerName -Path $Path
	Get-DomainGroupsMembersAll -Server $DomainBind -Path $Path
	Get-ServerAuditPolicy -Server $ComputerName -Path $Path
	Get-OUPermissions -Domain $DomainBind -Path $Path
    #Get-ServerQuickFixes -Server $ComputerName -Path $Path
	
}

Else
{
	#Write Errors to Log
	Write-ACTTDataLog -Message 'Write Errors to Log'
	$ErrorMesaage = '-------Insufficient Privileges used to run the Extractor.--------'
	$swExceptionLog.WriteLine($ErrorMesaage)
	Write-ACTTDataLog -Message $ErrorMesaage
}

	# Write ExtractEndTime
	Write-ACTTDataLog -Message 'Write ExtractEndTime'
	Write-ACTTConfigSettings -Setting 'ExtractEndDateAndTime' -Value $(Get-TimeDate)

}



Function Get-LocalData
{
	# Writing to Data Log
	Write-ACTTDataLog -Message 'Application Starts on Local Server....'
	# Write NDCAuditExtract_Version.ACTT
	$swVersion = New-Object System.IO.StreamWriter($(Join-Path $Path 'NDCAuditExtract_Version.ACTT'), $false, [System.Text.Encoding]::Unicode)
	$swVersion.WriteLine('[Version] NVARCHAR(MAX)')
	$swVersion.WriteLine($ScriptVersion)
	$swVersion.Close()

    $swVersion = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_Platform_WindowsLocalServer_ALL.ACTT'), $false, [System.Text.Encoding]::Unicode)
	$swVersion.WriteLine('[Version] NVARCHAR(MAX)')
	$swVersion.WriteLine($ScriptVersion)
	$swVersion.Close()

    
	# Check for Elevated Permissions
	$RunningElevated = $null -ne (whoami.exe /all | Select-String S-1-16-12288)

	If ($RunningElevated -eq $true)
	{
		Write-ACTTDataLog -Message '--------Correct Privileges used to run the extractor.--------'
		Write-ACTTConfigSettings -Setting 'PowerShell Version' -Value $psVersion 
		Write-ACTTConfigSettings -Setting 'ExtractStartDateAndTime' -Value $ScriptStartTime
		

		# Get Host and User name currently logged in - HostandUserName.actt
		Get-HostAndUserDetails
		
		# Get Credentials for the local server being audited
		#$Creds = Get-Credential -Message "Please provide your Local/Domain Admin credentials for this server $ComputerName"
		
		Write-ACTTDataLog -Message "Get Credentials for local admin $ComputerName"
			

		Get-LocalGroupsAll -Server $ComputerName -Path $Path
		Get-LocalUsersAll -Server $ComputerName -Path $Path
		Get-LocalWMIUsersAll -Server $ComputerName -Path $Path
		Get-LocalPwdPol -Path $Path
		Get-DomainSecPol -Server $ComputerName -Path $Path
		Get-DomainSecPolBoolean -Server $ComputerName -Path $Path
       		Get-LocalDomainGroups -Server $ComputerName -Path $Path	 
        	    
		Get-LocalGroupsMembersAll -Server $ComputerName -Path $Path
		Get-ServerUserRights -Server $ComputerName -Path $Path
		#Get-ServerQuickFixes -Server $ComputerName -Path $Path
		Get-ServerAuditPolicy -Server $ComputerName -Path $Path
		
		
	}

	Else
	{
		#Write Errors to Log
		Write-ACTTDataLog -Message 'Write Errors to Log'
		$ErrorMesaage = '-------Insufficient Privileges used to run the Extractor.--------'
		$swExceptionLog.WriteLine($ErrorMesaage)
		Write-ACTTDataLog -Message $ErrorMesaage
	}

	# Write ExtractEndTime
	Write-ACTTDataLog -Message 'Write ExtractEndTime'
	Write-ACTTConfigSettings -Setting 'ExtractEndDateAndTime' -Value $(Get-TimeDate)


}

#endregion Functions


#region Main
	Write-host 'Script analzying the current server environment'
	$osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
	$psVersion = $PSVersionTable.PSVersion.Major
	IF ($osInfo.ProductType -eq '2')
	{
		Import-Module ActiveDirectory
		# Create a Folder with the Forest name in the Audit Data Path to store the AD Forest audit data
		$Path = Join-Path $Path $ForestFQDN
		New-Item -Path $Path -Type Directory -Force | Out-Null
		
		# Create ACTTDataLog File
		$swACTTDataLog = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_DATA.LOG'), $false, [System.Text.Encoding]::Unicode)
		# Create exceptionlog.actt
		$swExceptionLog = New-Object System.IO.StreamWriter($(Join-Path $Path 'exceptionlog.actt'), $false, [System.Text.Encoding]::Unicode)
		$swExceptionLog.WriteLine('[LUMP] NVARCHAR(MAX)')
		
		# Create ACTT_CONFIG_SETTINGS.actt
		$swConfigSettings = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_CONFIG_SETTINGS.actt'), $false, [System.Text.Encoding]::Unicode)
		$swConfigSettings.WriteLine('SettingName NVARCHAR(MAX)' + $Delim + 'SettingValue NVARCHAR(MAX)')
		
		# Write ACTT_CONFIG_FIELDTERMINATOR.ACTT
		$swDelim = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_CONFIG_FIELDTERMINATOR.actt'), $false, [System.Text.Encoding]::Unicode)
		$swDelim.WriteLine($Delim)
		$swDelim.Close()
		Write-ACTTDataLog -Message 'Script running on DC'
		Write-host 'Script running on DC'
		Get-ConfigSettings
		Get-ADData
	}
	Else
	{		
		
		# Create a Folder with the server name
		$Path = Join-Path $Path $ComputerName
		New-Item -Path $Path -Type Directory -Force | Out-Null
		
		$swACTTDataLog = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_DATA.LOG'), $false, [System.Text.Encoding]::Unicode)
		# Create exceptionlog.actt
		$swExceptionLog = New-Object System.IO.StreamWriter($(Join-Path $Path 'exceptionlog.actt'), $false, [System.Text.Encoding]::Unicode)
		$swExceptionLog.WriteLine('[LUMP] NVARCHAR(MAX)')
		
		# Create ACTT_CONFIG_SETTINGS.actt
		$swConfigSettings = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_CONFIG_SETTINGS.actt'), $false, [System.Text.Encoding]::Unicode)
		$swConfigSettings.WriteLine('SettingName NVARCHAR(MAX)' + $Delim + 'SettingValue NVARCHAR(MAX)')
		
		# Write ACTT_CONFIG_FIELDTERMINATOR.ACTT
		$swDelim = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_CONFIG_FIELDTERMINATOR.actt'), $false, [System.Text.Encoding]::Unicode)
		$swDelim.WriteLine($Delim)
		$swDelim.Close()
		Write-ACTTDataLog -Message 'Script running on Local Server'
		Write-host 'Script running on Local Server'
		Get-ConfigSettings
		Get-LocalData
	}
	
	

#endregion Main


#region CleanUp

# Close ACTT_Config_Settings.actt
$swConfigSettings.Close()

# Close exceptionlog.actt
$swExceptionLog.Close()

# Close ACTTDataLog File
$swACTTDataLog.Close()
#endregion CleanUp
# SIG # Begin signature block
# MIIzuQYJKoZIhvcNAQcCoIIzqjCCM6YCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHnBkHTCdjyLGoMFyTkeEcsDe
# 2xKggi4rMIIFfzCCA2egAwIBAgIQGLXChEOQEpdBrAmKM2WmEDANBgkqhkiG9w0B
# AQsFADBSMRMwEQYKCZImiZPyLGQBGRYDY29tMRgwFgYKCZImiZPyLGQBGRYIRGVs
# b2l0dGUxITAfBgNVBAMTGERlbG9pdHRlIFNIQTIgTGV2ZWwgMSBDQTAeFw0xNTA5
# MDExNTA3MjVaFw0zNTA5MDExNTA3MjVaMFIxEzARBgoJkiaJk/IsZAEZFgNjb20x
# GDAWBgoJkiaJk/IsZAEZFghEZWxvaXR0ZTEhMB8GA1UEAxMYRGVsb2l0dGUgU0hB
# MiBMZXZlbCAxIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlPqN
# qqVpE41dp1s1+neM+Xv5zfUAKTrD10RAF9epFFmIIMH62VgMXOYYWBryNQaUAYPZ
# lvv/Tt0cCKca5XAWKp4DbBeblCmxfHsqEz3R/kzn/CHRHnQ3YMZRMorAccq82Ddx
# Kiwnw9o0W5SGD5A+zNXh9DjcCx0G5ROAaqiv7m3HYz2HrEvqdIuMkMoj7Y2ieMiw
# /PuIjVU8wmodltkBmGoAeOOcVYaWBZTpKy0NC/xYL7eHfMKdgRaa30pFVeZliN8D
# MiN/exbfr6iu00fQAsNxiZleH/6CLHuODdh+7KK00Wp2Wi9qz/IeOAGkj8j0jXFn
# nX5PHQWcVVv8E8sIK1S95xDxmhOsrMGkGA6G3F7a1qfI1WntvYBT98eUgZQ3whDq
# jypj622jjXLkUxlfuUeuBHB2+T9kSbapQHIhjAE3f97A/FOuzG0aerr6eNC5doNj
# OX31Bfp5W0WkhbX8D0Aexf7v+OsboqFkAkaNzSS2oaX7+G3XAw2r+slDmyimr+bo
# aLEo4vM+oFzFUeBQOXvjGBEnGtxXmSIPwsLu+HlhOvjtXINLbsczl2QWzC2arRPx
# x6HLr1hPj0eiyz7bKDPQ+N+U9l5OetL6NNFgppVDoqSVo5FUwh47wZKaqXZ8b1jP
# j/SS+IRsbKnCJ37+YXfkA2Mid9x8oMyRfBfwed8CAwEAAaNRME8wCwYDVR0PBAQD
# AgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFL6LoCtmWVn6kHFRpaeoBkJO
# kDztMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUAA4ICAQCDTvRyLG76
# 375USpexKf0BGCuYfW+o/6G18GRqZeYls7lO251xn7hfXacfEZIHCPoizan0yvZJ
# tYUocXRMieo766Zwn8g4OgEZjJXsw81p0GlkylmdWhqO+sRuGyYvGY32MWZ16oz6
# x/CG+rseou2HsLLtlSV76D2XPnDutIAHI/S4is4A7F0V+oNX04aHpUXMb0Y1BkPK
# NF1gIlmf4rdtRh6+2r374QP+Ruw+nJiPNwF7TF28wkz1iUXWK9FSmM1Q6+/uXxpx
# 9qRFRwv+pCd/07IneZ3GmxxTNJxSzzEJxIfwoJIn6HL9NYPltAZ7CuWYsm5TFY+x
# 5TZ5qS/O6+nAHd30T7K/q+H5hjp9tisYah3RiBOOU+iZvtUsr1XaLT7zizxnmp4s
# sHHryLhNkYu2uh/dT1/iq8SbM3fKGElML+mE7ZPAg2q2B76kgbY+GrEtzNnzwNfI
# wkh/IDKYJ9n6JU2yQ4oa5sJjTf5uHUhxV9Zd8/BZK8L3H5S7Iy3yCVLyq98xuUZ3
# ChL4FoKeS89uMrgKADP2xnAdIw1nnd67ZSPrTVk3sZO/uJVKTzjpU0V10sc27VmV
# x9YByc4o4xDoQ6+eAlUbNpuoFpchzdL2dx5JUalLl2T4jg4UIzKcidPhEmyU1ApK
# UXFQTbx0N8v1WC2UXROwuc0YDLR7v6RCLjCCBY0wggR1oAMCAQICEA6bGI750C3n
# 79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UE
# AxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoX
# DTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNl
# cnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQw
# H/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6
# dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXG
# XuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXn
# Mcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy
# 19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFY
# F/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+Skjqe
# PdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFg
# qrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJR
# R3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7Gr
# hotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9P
# MB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIB
# hjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV
# 5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8t
# tzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKh
# SLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO
# 7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WY
# IsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3
# AamfV6peKOK5lDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZI
# hvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1
# c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBD
# QTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVccl
# A8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9Q
# Ewsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDW
# VtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0
# UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huo
# wWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZw
# mCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rn
# H1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC
# 3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jz
# RWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEm
# CPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4w
# Er1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs
# 1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2
# oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG
# 9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3i
# Syn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKo
# Fr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9
# jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JE
# rpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOA
# CcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9r
# p/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvE
# lXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2
# uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRi
# CQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlH
# K+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwgga8
# MIIEpKADAgECAhALrma8Wrp/lYfG+ekE4zMEMA0GCSqGSIb3DQEBCwUAMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0Ew
# HhcNMjQwOTI2MDAwMDAwWhcNMzUxMTI1MjM1OTU5WjBCMQswCQYDVQQGEwJVUzER
# MA8GA1UEChMIRGlnaUNlcnQxIDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAy
# MDI0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvmpzn/aVIauWMLpb
# beZZo7Xo/ZEfGMSIO2qZ46XB/QowIEMSvgjEdEZ3v4vrrTHleW1JWGErrjOL0J4L
# 0HqVR1czSzvUQ5xF7z4IQmn7dHY7yijvoQ7ujm0u6yXF2v1CrzZopykD07/9fpAT
# 4BxpT9vJoJqAsP8YuhRvflJ9YeHjes4fduksTHulntq9WelRWY++TFPxzZrbILRY
# ynyEy7rS1lHQKFpXvo2GePfsMRhNf1F41nyEg5h7iOXv+vjX0K8RhUisfqw3TTLH
# j1uhS66YX2LZPxS4oaf33rp9HlfqSBePejlYeEdU740GKQM7SaVSH3TbBL8R6HwX
# 9QVpGnXPlKdE4fBIn5BBFnV+KwPxRNUNK6lYk2y1WSKour4hJN0SMkoaNV8hyyAD
# iX1xuTxKaXN12HgR+8WulU2d6zhzXomJ2PleI9V2yfmfXSPGYanGgxzqI+ShoOGL
# omMd3mJt92nm7Mheng/TBeSA2z4I78JpwGpTRHiT7yHqBiV2ngUIyCtd0pZ8zg3S
# 7bk4QC4RrcnKJ3FbjyPAGogmoiZ33c1HG93Vp6lJ415ERcC7bFQMRbxqrMVANiav
# 1k425zYyFMyLNyE1QulQSgDpW9rtvVcIH7WvG9sqYup9j8z9J1XqbBZPJ5XLln8m
# S8wWmdDLnBHXgYly/p1DhoQo5fkCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIH
# gDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2
# mi91jGogj57IbzAdBgNVHQ4EFgQUn1csA3cOKBWQZqVjXu5Pkh92oFswWgYDVR0f
# BFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUH
# AQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBY
# BggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAPa0eH3aZW+M4hBJH2UOR9hHbm04IHdEoT8/T3HuBSyZeq3jS
# i5GXeWP7xCKhVireKCnCs+8GZl2uVYFvQe+pPTScVJeCZSsMo1JCoZN2mMew/L4t
# pqVNbSpWO9QGFwfMEy60HofN6V51sMLMXNTLfhVqs+e8haupWiArSozyAmGH/6oM
# QAh078qRh6wvJNU6gnh5OruCP1QUAvVSu4kqVOcJVozZR5RRb/zPd++PGE3qF1P3
# xWvYViUJLsxtvge/mzA75oBfFZSbdakHJe2BVDGIGVNVjOp8sNt70+kEoMF+T6tp
# tMUNlehSR7vM+C13v9+9ZOUKzfRUAYSyyEmYtsnpltD/GWX8eM70ls1V6QG/ZOB6
# b6Yum1HvIiulqJ1Elesj5TMHq8CWT/xrW7twipXTJ5/i5pkU5E16RSBAdOp12aw8
# IQhhA/vEbFkEiF2abhuFixUDobZaA0VhqAsMHOmaT3XThZDNi5U2zHKhUs5uHHdG
# 6BoQau75KiNbh0c+hatSF+02kULkftARjsyEpHKsF7u5zKRbt5oK5YGwFvgc4pEV
# UNytmB3BpIiowOIIuDgP5M9WArHYSAR16gc0dP2XdkMEP5eBsX7bf/MGN4K3HP50
# v/01ZHo/Z5lGLvNwQ7XHBx1yomzLP8lx4Q1zZKDyHcp4VQJLu2kWTsKsOqQwggbJ
# MIIEsaADAgECAhM+AAAADRpkke5cm8AbAAMAAAANMA0GCSqGSIb3DQEBCwUAMFQx
# EzARBgoJkiaJk/IsZAEZFgNjb20xGDAWBgoJkiaJk/IsZAEZFghEZWxvaXR0ZTEj
# MCEGA1UEAxMaRGVsb2l0dGUgU0hBMiBMZXZlbCAyIENBIDIwHhcNMjIxMDI0MTYx
# ODI0WhcNMjcxMDI0MTYyODI0WjBUMRMwEQYKCZImiZPyLGQBGRYDY29tMRgwFgYK
# CZImiZPyLGQBGRYIZGVsb2l0dGUxIzAhBgNVBAMTGkRlbG9pdHRlIFNIQTIgTGV2
# ZWwgMyBDQSA2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1j4bG0g/
# XHK5sXt+DUnRULZp707tZ1o7XwXcqbeO+yC0trBRJkFeOiRuepTPbfT6nGECWd3K
# c/+6cAO/fCUYRmcRhLV+Ob1pPS3HIUMUo16Url4Yzw5QuncNy9VeVEKwJeQZ4PQG
# ngLRWOB29P5T5ln3iu4/IerH35GCglIG+e73ET802Ao69puicv4of76MdFOWTCG9
# 8jaOwgU11Sa8LTRjuQpOHX+lEZHVUiwhk3iDEHv+lELLbRu9Kefy2cWZTykKqPpj
# 4eBXkMNGIVE+hQK4JJ2+Rio8yCWOlLhayzmJaB0JMxfIxRrDRgDqInD/4xpRLxah
# tmaGDe22gY78fg+dSnrHiaa2FPYGkzuPz+0LBW4Lxz1IexfLatmPOyO4Qc3VWrOT
# vWNCX9xuwsPF/xIglGXFtPTyHlGYTBEU7gesOMnFog/iiJnBGDOHEG2IH8JDtMx3
# qNbNpP9xJVMF8SbUiXB7yZVaBSyDG18q4wuTRxXAm/UALEqDyFM9HiqdICjqXlij
# Jxsaw6bMx5k7wx/dBhlI6a8Ushm+ug2mpLFAfhD0/AYQ8EaeWwl/k5zB/6F1NTOc
# Sh5Qi56NS1nzssq0uXhV9LFCkcGsi0EHy7+hpW7H2T6r+rNj2wpvYrfgQPtiRv6T
# Y9PoOF9T9kS/3F3T6XM+Ok1J+XVdsHVzAmECAwEAAaOCAZIwggGOMBIGCSsGAQQB
# gjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFORO5B4biZz/FY+5t8LXKt/axJiG
# MB0GA1UdDgQWBBRmnUV9KPN4yL5ro74F6Vqv5hGaxDAZBgkrBgEEAYI3FAIEDB4K
# AFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNV
# HSMEGDAWgBRDSJReCIF5BlOIS5XgiHDoT+J7vTBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vcGtpLmRlbG9pdHRlLmNvbS9DZXJ0RW5yb2xsL0RlbG9pdHRlJTIwU0hB
# MiUyMExldmVsJTIwMiUyMENBJTIwMigzKS5jcmwwdgYIKwYBBQUHAQEEajBoMGYG
# CCsGAQUFBzAChlpodHRwOi8vcGtpLmRlbG9pdHRlLmNvbS9DZXJ0RW5yb2xsL1NI
# QTJMVkwyQ0EyX0RlbG9pdHRlJTIwU0hBMiUyMExldmVsJTIwMiUyMENBJTIwMigz
# KS5jcnQwDQYJKoZIhvcNAQELBQADggIBAJXCPHYpkyIv99rQspqRqnJ6OxQZ7xBk
# zPap/d1ZyVNJ1U4sE76jpt2j+cjtt7PnW30GBa5HufsLjlP/yCVL+n4L//4FGQfs
# Ei5Z37kzNE9RL4rXXSbUCCeGHIuPn9+h9O1jyaeTGQ98sDoXBGsQj8wJmtaND3CA
# 6c2JSGkipZ31+NQfeKoJnN5nfeOrbD61TT6lOExXAc46Cz/v1jvQXt9N1QhOvJQD
# yeMpV9TLKPnKSH5Zwq01dwEqwM5r036oREnGKwh6FujrhKS0XQXn8pGOjYkjRnAA
# /VbXULF33Oa5uM7//l2lGH2/Fwd37bio3Nji5YhRuWqcf2x1rhMQuhaa1YHt0BcO
# VRoMLQnyI2K16gYPQb2bOUYs0d8MklQXjVRfg125VD+3Hj1GkX30uklExAB25x8/
# CG+jvrHIST/t4ZgfntzGXbiWxwp31ej1n3+pSlwb79Hx2VY0vCQm6IP0vSxiWU44
# 5mf57HPh98BuseV6KoiCwnkRxcunbFrzUNmT8VdxheFCYWpW+bvAiDq4apyQJffH
# gS/pJLfi8OZRoNWQQ2FY51BWXRcCVx+nugdSToaU+o+nG9OdwEhv6g9SbaMLYK/8
# SSMNYS26+c8XaLSBPBzmjOBFA6K+EYGSSl3oZ8tvRO6ymIWhFrXYWNJYEDt35ZKr
# Ww0Mse8CfH/wMIIGyzCCBLOgAwIBAgITNAAAAAlkOlYZVkm5PQAAAAAACTANBgkq
# hkiG9w0BAQsFADBSMRMwEQYKCZImiZPyLGQBGRYDY29tMRgwFgYKCZImiZPyLGQB
# GRYIRGVsb2l0dGUxITAfBgNVBAMTGERlbG9pdHRlIFNIQTIgTGV2ZWwgMSBDQTAe
# Fw0yMjEwMjQxNTEyNTdaFw0zMjEwMjQxNTIyNTdaMFQxEzARBgoJkiaJk/IsZAEZ
# FgNjb20xGDAWBgoJkiaJk/IsZAEZFghEZWxvaXR0ZTEjMCEGA1UEAxMaRGVsb2l0
# dGUgU0hBMiBMZXZlbCAyIENBIDIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCdh2ei/rw5+KeL/fUf4nOks6N/N7gXupty6ujzt1f8Gq+lND747Jm9WMOC
# RWKCaWyANId/fTmAmBuBPKZrN4NVrbp222IxerrD7laqTkqODbvjZz5GDjYmYdUK
# VnJ9zMLU4UHC+7o0CoYjH5iZhG5jV6fhUVwMGdBN19fqlSx9uvPOhxT+KIzsh3/Z
# 2+E2G7KqzNXh1iFydDPjkkNnM/L7rFy9bWVdk52CmGnaTdWmZge6NtGdwO9ZxnCH
# FCnF9oezkECxeFsL36siR/3asi8ZdoQiSmL9ry03gzh5FT6YcnEoc6kLc2Hlsqdg
# Bh9TByEVXur+hfKfTb/WH/B3J2kuD4Fceq/ajQqFvq9HHgQ3XniBYjMkjfCHSNLb
# TC7mp3HjLkHUuE/fj40h5Rlct6kbo6iUhYIAdRWfLZLYuXoq6BqeFrAd45bVgOew
# tX2x95OHkKdWagd9H6SCuxYed27tc661FMjWav0GxEd+ctjRFeL+E458Jh408x3s
# 8G0P47CoCH5SkHtFByPzsfPkUrl/PEW4wJkyNEH2MiTv61V3KsRXoQ6LtlBXeL5F
# sdexPxHwRozUg49iejmt/qQKN+lHExTpW9Q+cFFDps015ZzPZBpsBDtgXxq8ilqW
# hCLT7lFVGWpZolRjhOkfdxI2vN+BjYPhaPT3eKYKjVz4GDztmQIDAQABo4IBljCC
# AZIwEgYJKwYBBAGCNxUBBAUCAwMAAzAjBgkrBgEEAYI3FQIEFgQUjoGu1O9aOkHj
# tpJRm6hymAINFHwwHQYDVR0OBBYEFENIlF4IgXkGU4hLleCIcOhP4nu9MBEGA1Ud
# IAQKMAgwBgYEVR0gADAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8E
# BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBATAfBgNVHSMEGDAWgBS+i6ArZllZ+pBx
# UaWnqAZCTpA87TBYBgNVHR8EUTBPME2gS6BJhkdodHRwOi8vcGtpLmRlbG9pdHRl
# LmNvbS9DZXJ0RW5yb2xsL0RlbG9pdHRlJTIwU0hBMiUyMExldmVsJTIwMSUyMENB
# LmNybDBuBggrBgEFBQcBAQRiMGAwXgYIKwYBBQUHMAKGUmh0dHA6Ly9wa2kuZGVs
# b2l0dGUuY29tL0NlcnRFbnJvbGwvU0hBMkxWTDFDQV9EZWxvaXR0ZSUyMFNIQTIl
# MjBMZXZlbCUyMDElMjBDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAIk6OR120jEu
# nUK6jhtjh8SXfNaNjJ6SvNBrWEH/YU2JsyN7Wq8FVpOLlx22uEssRtbRsxCnKBCm
# FmPIKQxIlSdRcpXNLgbR3IQ30+5v7rUKXJA02u5nqTrnDKYA9waTrDwc218NEQlK
# JXWKSPXvRTOLSgJg7D87YsHO3qDG/JGcECy6R9O37becLGXuna8qECtQ8weKK06U
# XK2Q9516T0SNqLYCgaVDfffCH1oYyd99OSBcLa6Shk+YrbGaZmvEpRHUtYMvaiqZ
# +RZgOpna7htsvLc1wnyRFa/HGORPqRxzlgWEEBqd/YRBjPFMgkzVTvPapNpFl707
# +jZ2BpR3gOqYr56E/9PNV6OHs7mO+6/3bjG9VD6wT8y/neReo6HpYvPEePxw9yp0
# vIgd7StB/6QwFzgdIcrG10ABk6lJMkGoAXa5ZOPEMzLeHzluXLvKkqanHoqeWKnK
# WZk2T8C8jQlUs2mti/Rc06xIgHgFQ1m9Ni5nWg0yzAf7UyTOq6Mq/EC6nOcaksqS
# +4212GELIHFiMX4JpqLOiXaM81nkSEKubQ5f2PFM4rWh0HMKazry7Gr9cvhVrEtm
# 1HcT5XXcfNTmkSckVDyjxQ4QHe5NJVr7EGkmM9AjcDYxGYk9zg+oQmbNKHIdbxYi
# 9vIdyXRUdN/gwvQVQJMBhjiaafc3HgcSMIIIBTCCBe2gAwIBAgITMAATKxh1deAb
# C4C7lQABABMrGDANBgkqhkiG9w0BAQsFADBUMRMwEQYKCZImiZPyLGQBGRYDY29t
# MRgwFgYKCZImiZPyLGQBGRYIZGVsb2l0dGUxIzAhBgNVBAMTGkRlbG9pdHRlIFNI
# QTIgTGV2ZWwgMyBDQSA2MB4XDTI1MDMxNDE3NDU0NFoXDTI3MDMxNDE3NDU0NFow
# gcYxCzAJBgNVBAYTAlVTMRIwEAYDVQQIEwlUZW5uZXNzZWUxEjAQBgNVBAcTCUhl
# cm1pdGFnZTEdMBsGA1UEChMURGVsb2l0dGUgU2VydmljZSBMTFAxGjAYBgNVBAsT
# EVVTIEN5YmVyIFNlY3VyaXR5MScwJQYDVQQDEx5VUyBDeWJlciBTZWN1cml0eSBD
# b2RlIFNpZ25pbmcxKzApBgkqhkiG9w0BCQEWHHVzZHBlbmdpbmVlcmluZ0BkZWxv
# aXR0ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPmPiaHzYy
# VHenmt7SxcWoGcCqBNhbWvSpe2nYsO0TAshmhbT4xTkvYdCBmxMEod7MD4Syjx8G
# Z66EHkfpm79rtwfyOx8GrOoYBVjQj/JdtmpfZvAsRgJqm3B4j3dHWDoGdJd6HkNI
# nDq9V0LqQ98YA1zmSQimSSZ1AfZy3WnkeuDPiFPWbf2ZpFAEll2BzGrgwQ479VCQ
# P8GNgRfjOfS+WG3ktmhkxGPL9atGrC7HQHeBYpURSSS/zXzuo7A9LSm6Cy4HO2if
# 0KEBch2OpcDkiBKS51urKpfIoF/S4PLlPgd8kZa5ZrJj6TKdNTJ8UH00S+cM5Pk1
# h5V2Z4R0Yq/9AgMBAAGjggNbMIIDVzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3
# FQiBgb1Jhb6FE4LVmzyD144HhvHJClyDyvctwvMyAgFkAgEfMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMAsGA1UdDwQEAwIHgDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUF
# BwMDMB0GA1UdDgQWBBQnE6wXJw2OI8cmzJ+ghpM3eqLigjAfBgNVHSMEGDAWgBRm
# nUV9KPN4yL5ro74F6Vqv5hGaxDCCAT4GA1UdHwSCATUwggExMIIBLaCCASmgggEl
# hoHSbGRhcDovLy9DTj1EZWxvaXR0ZSUyMFNIQTIlMjBMZXZlbCUyMDMlMjBDQSUy
# MDYoMSksQ049YW0wMTQzdzAwMixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2Vy
# dmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1kZWxvaXR0ZSxE
# Qz1jb20/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNz
# PWNSTERpc3RyaWJ1dGlvblBvaW50hk5odHRwOi8vcGtpLmRlbG9pdHRlLmNvbS9D
# ZXJ0ZW5yb2xsL0RlbG9pdHRlJTIwU0hBMiUyMExldmVsJTIwMyUyMENBJTIwNigx
# KS5jcmwwggFUBggrBgEFBQcBAQSCAUYwggFCMHkGCCsGAQUFBzAChm1odHRwOi8v
# cGtpLmRlbG9pdHRlLmNvbS9DZXJ0ZW5yb2xsL2FtMDE0M3cwMDIuYXRyYW1lLmRl
# bG9pdHRlLmNvbV9EZWxvaXR0ZSUyMFNIQTIlMjBMZXZlbCUyMDMlMjBDQSUyMDYo
# MSkuY3J0MIHEBggrBgEFBQcwAoaBt2xkYXA6Ly8vQ049RGVsb2l0dGUlMjBTSEEy
# JTIwTGV2ZWwlMjAzJTIwQ0ElMjA2LENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBT
# ZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWRlbG9pdHRl
# LERDPWNvbT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
# dGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAgEABQzt2l+pK5IR5+bvszwl
# fjK9Qfn+Ehpg5lkKED8eGNtA0/lDb2bDWybTJ4AOdtV7XbXUkY0ryUFE4yVls+jj
# mt5wvD8nsqYiaGFtzKvCII1q6jaRte3wr2la+xA5seqGrvM0NUJxSPe0F3c3BJVO
# KhVdbfcXN8MYs4vquiJuCNPxm/Bs3Y4A36BwijlUczCmUJxokmvp69fV5sqfm3TG
# lbj+k9n39rIXrl6MyrtpLdkG/ZjM+aiM/2m17Dbkk8SdqMGOQn9S/2Ft1Sn0frP7
# 0pBlypSQdq2VMvqlOAO9ooePNuXcuVsHFqCthrT1mAQNhxwD9rtxbH2V7GlWUrbJ
# XfLKyGtHtHOSLopxomXj+CL9Hmrwe7J9A34N6QXXvZaHFzOlGM3O2Pr9j7hNEo1v
# kw52etBJtlyTlKxE/JNnfv8rjPUV5tQVDTOvu6wJp77yY+4PmKEcLoxrPsynWomH
# m2Nbhu5gICXakAAKOBKDenk9ZdKUa+6havU/fFTq8ysIbE7bdxmfzLo5o1qtctGx
# 2JcEtf64NOuvevH3Q5/OUltbc4Fa5Ctylpi1PBowm560pbRwT88eJU6qp0W0ysPD
# 5ytEesR3pW/SfE7UNAxCCMx3r3KzGvKH+NpnT9o/Lfg3vNtvXZKU5GsTFNKKzLoI
# oA2/mJyISIhQKk7gqVoNRmExggT4MIIE9AIBATBrMFQxEzARBgoJkiaJk/IsZAEZ
# FgNjb20xGDAWBgoJkiaJk/IsZAEZFghkZWxvaXR0ZTEjMCEGA1UEAxMaRGVsb2l0
# dGUgU0hBMiBMZXZlbCAzIENBIDYCEzAAEysYdXXgGwuAu5UAAQATKxgwCQYFKw4D
# AhoFAKBAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMCMGCSqGSIb3DQEJBDEW
# BBRoZo27LRsVm1Q6sdDLH2OA3rCl9TANBgkqhkiG9w0BAQEFAASCAQBiTsGnT+y4
# FJAJNqjFisXFDRTWOk9cgmtbsjH3J8P/g7vXavo3MyAAS2pMSRGD7yrby+3bk2/L
# L8yZM5BfIN/wiUGQJIU4nYpX9vfMXJaksDBTx1X5whO+16h7kCmxuoeIOIJliK9Y
# 2XZvY2Rx+N5WC/IRxhFY3aIVnWYwx1xOF6a6wIHZMsWt8Hdqhinr0Bk95cthzYwT
# SIzajlg0am1Tf6+p4uHvw2DAh76JGZtUuJSDkTF08CrgYPIMaeGR1DZ6vVqwqDw/
# +4io4qwzAzFil/0qHS+u/S5jnMKAB08ryr1dX0VM8KunVd//jjYa3cPRlCsZLmMg
# 6RO9ODNQ5C5IoYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# C65mvFq6f5WHxvnpBOMzBDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDMyNTE3NDA1NFowLwYJKoZI
# hvcNAQkEMSIEICa0FMlKG/uIfK81PcW/WzbYKtr1sj2+R3I1iH9lbZE2MA0GCSqG
# SIb3DQEBAQUABIICAH7I9JbQCNI1as34b+uZsZBSpqWd89huXG7wcrkAfmFw8wJQ
# yV8k0VlyPVzvvDiPbOuS9r97mykYo0EJ4VQyGDW+QQEPABnYS66b7GkFdcU1oqaM
# ulOC8OWY5CNh0MwxpelH8fnJ1Nr0mHgXQPTKckAjb9tEaxEvFZRw2Zd7jPu7dhwD
# x0xDA2ulYTX3xebfAzVaQQ83Z02EmGRbE9s1LjzIvr4ayl+6lRcxJVQCa8rYtXBL
# XK9RhLY5rCDn4YkcTwve8Xz3v+4WUYxx9rcM5XZ5LxSMgFWaCnWM7u1W3iymKzj9
# kRQN4ErlE4JIQ2tQHszqVyzxUG8l2ZTVJeF5SjYXGC9R9dd8opOrSFcGVw9G07MH
# hvLETHu/XQ09aJ6Dt674Tvq0mTt/pcJyMGpGZci11+G9MlwpUDH7NkaClPRyF4aO
# 0UZzEtSPQC83Sdi7iiTrGst8B4P9wBr+gRZbys5uO1JKttt30XDqQvieXARabh4N
# WmphxJ0e0l6EZano2Zq4noBpn2veuoH8lTtL5JtcHQd8XHpgvLD7Nah7XLBuYl4v
# 3e9R5lbCL0FSuLci0C5Jh8stajWt12x6sDg0qDqjqGr9U7KimH8KnJVcd0KnJ7LU
# ap6u7kHIvQnvtQPKRXIhyBmlyjcU4c3h/Bcn/NOo2sI8ILvycv4rmizbe0C/
# SIG # End signature block
