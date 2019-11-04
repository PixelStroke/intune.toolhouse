<#PSScriptInfo
	.VERSION 1.0

	.GUID ef633ce0-3bae-4f98-9d51-363cc9821a9e

	.AUTHOR shonpt@outlook.com

	.COMPANYNAME

	.COPYRIGHT 2019 Shon Thomas. All rights reserved

	.TAGS Intune AzureAD Policy Groups Assignments Audit MDM Graph

	.LICENSEURI

	.PROJECTURI https://github.com/pixelstroke/Intune.ToolHouse/Scripts

	.ICONURI

	.EXTERNALMODULEDEPENDENCIES

	.REQUIREDSCRIPTS

	.RELEASENOTES
	First release supports:
	Mapping Azure AD group to Intune configuration policy targets
	Retrieving all Intune configuration policies and their targets

	.PRIVATEDATA
#>
<#
	#Requires -Module AzureAD
	#Requires -Module Microsoft.Graph.Intune
#>

<#	
	.NOTES
	===========================================================================
	 Created by:			Shon Thomas
	 Filename:			Get-IntuneGroupAssignments.ps1
	 Required Modules:		AzureAD, Microsoft.Graph.Intune
	 IMPORTANT:			YOU MUST RUN Connect-MSGraph -AdminConsent AND 
	 				AUTHORIZE THE POWERSHELL MODULE IN YOUR TENANT
	===========================================================================

	.SYNOPSIS
	Get all Intune group assignments for policy targets [included/excluded]
	
	.DESCRIPTION
	This script will connect to Azure AD for the named group ObjectId and use this ID to query all Intune policy objects for any target assignments

	.EXAMPLE
	Authenticate with Azure AD and MS Graph and search for "My Group"
	.\Get-IntuneGroupAssignments.ps1 -Name "My Group"

	All new queries are cashed into global variables to minimize network requests
	.\Get-IntuneGroupAssignments.ps1 -Name "My Other Group"

	Minimize the chatter about policies being retrieved
	.\Get-IntuneGroupAssignments.ps1 -Name "My Group"-Quiet

	Include all policies in the result even though they are not assigned directly
	.\Get-IntuneGroupAssignments.ps1 -Name "Some Group" -All -Quiet

	Refresh the cash to query Azure AD and MS Graph
	.\Get-IntuneGroupAssignments.ps1 -Name "My New Group" -Refresh

	.LINK
	https://github.com/pixelstroke/

#>
#Requires -PSEdition Desktop -Version 5
param (
	[Parameter(Mandatory = $true,
	HelpMessage = "Specify a group in Azure Active Directory")]
	[String]$Name,

	[Parameter(Mandatory = $false,
	HelpMessage = "Limit output in the console")]
	[Switch]$Quiet,

	[Parameter(Mandatory = $false,
	HelpMessage = "Do not limit Intune policy results to the searched Azure Active Directory Group")]
	[Switch]$All,

	[Parameter(Mandatory = $false,
	HelpMessage = "Refresh the cache by calling the MS Graph API")]
	[Switch]$Refresh
)

### Script ###
if ($Refresh) { $Global:isStale = $false }

### Required Modules ###
$requiredModules = @('Microsoft.Graph.Intune', 'AzureAD')
foreach ($module in $requiredModules)
{
	if (-not (Get-Module -Name $module -ListAvailable)) 
	{
		Write-Host -ForegroundColor Red "Missing required module " -NoNewline
		Write-Host $module

		$input = $null
		while(-not ($input -imatch "y|yes|n|no")) {

			$input = Read-Host -Prompt "Install ${module}? [y/n]"

			if ($input -imatch "y|yes") {
				Install-Module -Name $module -Scope CurrentUser -AllowClobber -Force
			} else {
				Write-Host -ForegroundColor Red "Module not installed: "
				Write-Host $module
				Exit
			}
		}
	}

	Import-Module -Name $module -Force
}

### Authenticate with Azure AD ###
try { $null = Get-AzureADTenantDetail }
catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException]
{
	try {
		Write-Host -ForegroundColor Yellow "Connecting to Azure AD..."
		$null = Connect-AzureAD
	} 
	catch [System.Exception]
	{
		Write-Host -ForegroundColor Red "Unable to connect to Azure AD`n"
		$_.Exception.Message
		Exit
	}
}
Write-Host -ForegroundColor Green "Connected to Azure AD"

#
# Azure AD - Get group
#
Write-Host -ForegroundColor Cyan "Searching Azure AD for '${Name}'`n"
$filter = "DisplayName eq '${Name}'"
$Group = Get-AzureADGroup -Filter "$filter"

if (-not $group)
{
	Write-Host -ForegroundColor Yellow "Couldn't find '${Name}' within the directory.`n"
	Exit
}

### Authenticate with MS Graph ###
try
{
	Write-Host -ForegroundColor Yellow "Connecting to Microsoft Graph..."
	$null = Connect-MSGraph
}
catch [System.Exception]
{
	Write-Host -ForegroundColor Red "Unable to connect to Microsoft Graph `n"
	$_.Exception.Message
	Exit
}
Write-Host -ForegroundColor Green "Connected to Microsoft Graph"


### Class IntuneObject ###
class IntuneObject
{
	[String]$Id
	[String]$Type
	[String]$PolicyName = "Empty"
	[Bool]$IsIncluded = $false
	[Bool]$IsExcluded = $false
	[Array]$IncludedGroups = "None"
	[Array]$ExcludedGroups = "None"
}

### Function Get-IntuneAssignments ###
function Get-IntuneAssignments
{
	param
	(
		[CmdletBinding()]
		[Parameter(Mandatory = $true,
			Position = 0,
			HelpMessage = "Specify object returned from MS Graph API",
			ParameterSetName = "Policies")]
		[Object]$Policy,
		[Parameter(Mandatory = $true,
			HelpMessage = "Retrieve Conditional Access Settings only",
			ParameterSetName = "CA")]
		[Switch]$ConditionalAccess,
		[Switch]$Quiet
	)
	
	process
	{
		if ($ConditionalAccess)
		{
			$IntuneObj = Get-IntuneConditionalAccessSetting | ForEach-Object {
				$oDataType = ($_ | Get-Member | Select-Object -First 1).TypeName.Replace('microsoft.graph.', '')
				if (-not $Quiet) 
				{
					Write-Host -ForegroundColor Blue "Retrieving Conditional Access settings..." -NoNewline
					Write-Host -ForegroundColor Yellow "[${oDataType}] "
				}

				$data = @{
					Id = $_.id
					Type = $oDataType
					IncludedGroups = $_.includedGroups
					ExcludedGroups = $_.excludedGroups
				}
				
				return New-Object -TypeName IntuneObject -Property $data
			}
			
			return $IntuneObj
		}
		$oDataType = ($Policy | Get-Member | Select-Object -First 1).TypeName.Replace('microsoft.graph.', '')
		if (-not $Quiet) {
			Write-Host -ForegroundColor Blue "Retrieving assignment policy:" -NoNewline
			Write-Host -ForegroundColor Yellow "[${oDataType}] " -NoNewline
			Write-Host -ForegroundColor White "$($Policy.displayName)"
		}

		#
		# Return IntuneObject
		#
		$IntuneObj 			= New-Object -TypeName IntuneObject
		$IntuneObj.Id 			= $Policy.id
		$IntuneObj.PolicyName 		= $Policy.displayName
		$IntuneObj.Type 		= $oDataType
		$IntuneObj.IncludedGroups 	= $Policy.assignments.target | Where-Object { $_.'@odata.type' -inotmatch 'exclusion' }
		$IntuneObj.ExcludedGroups 	= $Policy.assignments.target | Where-Object { $_.'@odata.type' -imatch 'exclusion' }
		return $IntuneObj
	}
}

function Get-IntuneIsAssigned {
	param (
		[CmdletBinding()]
		[Parameter(Mandatory = $true,
			Position = 0,
			HelpMessage = "Specify object that is a type of IntuneObject",
			ParameterSetName = "SingleIntuneObject")]
		[IntuneObject]$IntuneObject,
		[Parameter(Mandatory = $true,
			Position = 0,
			HelpMessage = "Specify a list of objects that are type of IntuneObject",
			ParameterSetName = "ManyIntuneObjects")]
		[Array]$IntuneObjectList,
		[Parameter(Mandatory = $true,
			HelpMessage = "Specify the AzureAD ObjectId")]
		[String]$ObjectId,
		[Parameter(HelpMessage = "Use the switch to include all objects unfiltered")]
		[Switch]$All
	)
	process 
	{

		if ($IntuneObject) {
			if ($IntuneObject.IncludedGroups -imatch $ObjectId) { $IntuneObject.IsIncluded = $true } else { $IntuneObject.IsIncluded = $false }
			if ($IntuneObject.ExcludedGroups -imatch $ObjectId) { $IntuneObject.IsExcluded = $true } else { $IntuneObject.IsExcluded = $false }

			if ($All) { return $IntuneObject }
			return $IntuneObject | Where-Object { $_.IncludedGroups -imatch $ObjectId -or $_.ExcludedGroups -imatch $ObjectId }
		}

		if ($IntuneObjectList) {
			[System.Collections.ArrayList]$List = @()
			foreach ($iObj in $IntuneObjectList) {
				if ($All) 
				{
					[Void]$List.Add( (Get-IntuneIsAssigned -IntuneObject $iObj -ObjectId $ObjectId -All) )
				} else 
				{
					$objectToAdd = Get-IntuneIsAssigned -IntuneObject $iObj -ObjectId $ObjectId
					if ($objectToAdd) { [Void]$List.Add($objectToAdd) }
				}
			}
			return $List
		}
	}
}

try  ## Collect configurations
{
	#
	# Intune - Collect configuration data
	#
	if (-not $isStale) {
		Write-Host -ForegroundColor Cyan "Collecting Intune configuration objects...`n"
		$Global:DeviceConfigAssignments 	= Get-IntuneDeviceConfigurationPolicy -Select id, displayName -Expand assignments| ForEach-Object { Get-IntuneAssignments -Policy $_ -Quiet:$Quiet }
		$Global:DeviceComplianceAssignments 	= Get-IntuneDeviceCompliancePolicy -Select id, displayName -Expand assignments | ForEach-Object { Get-IntuneAssignments -Policy $_ -Quiet:$Quiet }
		$Global:MobileAppAssignments 		= Get-IntuneMobileApp -Select id, displayName -Expand assignments | ForEach-Object { Get-IntuneAssignments -Policy $_ -Quiet:$Quiet }
		$Global:AppProtectionPoliciesAndroid 	= Get-IntuneAppProtectionPolicyAndroid -Select id, displayName -Expand assignments | ForEach-Object { Get-IntuneAssignments -Policy $_ -Quiet:$Quiet }
		$Global:AppProtectionPoliciesiOS 	= Get-IntuneAppProtectionPolicyiOS -Select id, displayName -Expand assignments | ForEach-Object { Get-IntuneAssignments -Policy $_  -Quiet:$Quiet }
		$Global:WindowsInformationProtection 	= Get-IntuneWindowsInformationProtectionPolicy -Select id, displayName -Expand assignments | ForEach-Object { Get-IntuneAssignments -Policy $_ -Quiet:$Quiet }
		$Global:ConditionalAccessSettings 	= Get-IntuneAssignments -ConditionalAccess -Quiet:$Quiet
	}
} 
catch [System.Exception]
{
	Write-Host -ForegroundColor Red "Script encountered an error retrieving Intune policies..."
	Write-Host -ForegroundColor Red $_.Exception.Message
}
finally
{
	$Global:isStale = $false
}

try ## Collect assignments
{
	#
	# Global assignment list
	#
	[System.Collections.ArrayList]$Global:IntuneGroupAssignments = @()

	#
	# Intune - Search for named group in assignments
	#
	Write-Host -ForegroundColor Cyan 'Retrieving group assignments for ' -NoNewline
	Write-Host -ForegroundColor White "${Name}"
	Write-Host -ForegroundColor Cyan "Group ObjectId " -NoNewline
	Write-Host -ForegroundColor White "$($Group.ObjectId)"

	Get-IntuneIsAssigned -IntuneObjectList $DeviceConfigAssignments -ObjectId $Group.ObjectId -All:$All | ForEach-Object { [Void]$IntuneGroupAssignments.Add($_) }
	Get-IntuneIsAssigned -IntuneObjectList $DeviceComplianceAssignments -ObjectId $Group.ObjectId -All:$All | ForEach-Object { [Void]$IntuneGroupAssignments.Add($_) }
	Get-IntuneIsAssigned -IntuneObjectList $MobileAppAssignments -ObjectId $Group.ObjectId -All:$All | ForEach-Object { [Void]$IntuneGroupAssignments.Add($_) }
	Get-IntuneIsAssigned -IntuneObjectList $AppProtectionPoliciesAndroid -ObjectId $Group.ObjectId -All:$All | ForEach-Object { [Void]$IntuneGroupAssignments.Add($_) }
	Get-IntuneIsAssigned -IntuneObjectList $AppProtectionPoliciesiOS -ObjectId $Group.ObjectId -All:$All | ForEach-Object { [Void]$IntuneGroupAssignments.Add($_) }
	Get-IntuneIsAssigned -IntuneObjectList $WindowsInformationProtection -ObjectId $Group.ObjectId -All:$All | ForEach-Object { [Void]$IntuneGroupAssignments.Add($_) }
	Get-IntuneIsAssigned -IntuneObjectList $ConditionalAccessSettings -ObjectId $Group.ObjectId -All:$All | ForEach-Object { [Void]$IntuneGroupAssignments.Add($_) }

	#
	# Intune - Display all assignments
	#
	if ($IntuneGroupAssignments.Count -eq 0)
	{
		Write-Host -ForegroundColor Green "Group ${Name} is not part of any Intune policy assignments"
	}
	else
	{
		if (-not $All) 
		{
			Write-Host -ForegroundColor Cyan "Total number of assignments: " -NoNewline
			Write-Host -ForegroundColor White "($($IntuneGroupAssignments.Count))"
			$IntuneGroupAssignments | Sort-Object -Property Type, IsIncluded | Select-Object Type, PolicyName, IsIncluded, IsExcluded | Format-Table -AutoSize
		}
		else 
		{
			Write-Host -ForegroundColor Cyan "Total number of policies: " -NoNewline
			Write-Host -ForegroundColor White "($($IntuneGroupAssignments.Count))"
			$IntuneGroupAssignments | Select-Object Type, DisplayName, IsIncluded, IsExcluded | Group-Object Type | Sort-Object Name
		}

		Write-Host -ForegroundColor White "`nMore details available in " -NoNewline
		Write-Host -ForegroundColor Green '$IntuneGroupAssignments'
	}

	#
	# Minimize requests if Intune environment hasn't changed between queries
	#
	$Global:isStale = $true
}
catch [System.Exception] {
	Write-Host -ForegroundColor Red "Script encountered an error retrieving policy assignments...`n"
	Write-Host -ForegroundColor Red $_.Exception.Message

	$Global:isStale = $false
}
