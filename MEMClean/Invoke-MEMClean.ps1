
#region Functions
function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )
    
    $userUpn = New-Object 'System.Net.Mail.MailAddress' -ArgumentList $User
    
    if ($userUpn.Host -like '*onmicrosoft.com*') {
        $tenant = Read-Host -Prompt 'Please specify your Tenant name i.e. company.com'
        Write-Host
    }
    else {
        $tenant = $userUpn.Host
    }
    
    
    Write-Host 'Checking for AzureAD module...'
    
    $AadModule = Get-Module -Name 'AzureADPreview' -ListAvailable
    
    if ($null -eq $AadModule) {
    
        Write-Host 'AzureAD PowerShell module not found, looking for AzureADPreview'
        $AadModule = Get-Module -Name 'AzureADPreview' -ListAvailable
    
    }
    
    if ($null -eq $AadModule) {
        Write-Host
        Write-Host 'AzureAD Powershell module not installed...' -f Red
        Write-Host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        Write-Host "Script can't continue..." -f Red
        Write-Host
        exit
    }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
    if ($AadModule.count -gt 1) {
    
        $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
    
        $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }
    
        # Checking if there are multiple versions of the same module found
    
        if ($AadModule.count -gt 1) {
    
            $aadModule = $AadModule | Select-Object -Unique
    
        }
    
        $adal = Join-Path $AadModule.ModuleBase 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
        $adalforms = Join-Path $AadModule.ModuleBase 'Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'
            
    
    }
    
    else {
    
        $adal = Join-Path $AadModule.ModuleBase 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'
        $adalforms = Join-Path $AadModule.ModuleBase 'Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'
    
    }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'
    
    $redirectUri = 'urn:ietf:wg:oauth:2.0:oob'
    
    $resourceAppIdURI = 'https://graph.microsoft.com'
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
    try {
    
        $authContext = New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext' -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters' -ArgumentList 'Auto'

        $userId = New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier' -ArgumentList ($User, 'OptionalDisplayableId')
             
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
    
        # If the accesstoken is valid then create the authentication header
    
        if ($authResult.AccessToken) {
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = 'Bearer ' + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }
    
            return $authHeader
    
        }
    
        else {
    
            Write-Host
            Write-Host 'Authorization Access Token is null, please re-run authentication...' -ForegroundColor Red
            Write-Host
            break
    
        }
    
    }
    
    catch {
    
        Write-Host $_.Exception.Message -f Red
        Write-Host $_.Exception.ItemName -f Red
        Write-Host
        break
    
    }
    
}
Function Get-ManagedAppProtection() {

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy
    .EXAMPLE
    Get-ManagedAppProtection -id $id -OS "Android"
    Returns a managed app protection policy for Android configured in Intune
    Get-ManagedAppProtection -id $id -OS "iOS"
    Returns a managed app protection policy for iOS configured in Intune
    Get-ManagedAppProtection -id $id -OS "WIP_WE"
    Returns a managed app protection policy for Windows 10 without enrollment configured in Intune
    .NOTES
    NAME: Get-ManagedAppProtection
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id,
        $OS    
    )
    
    $graphApiVersion = 'Beta'
    
    try {
        
        if ($id -eq '' -or $null -eq $id) {
        
            Write-Host 'No Managed App Policy id specified, please provide a policy id...' -f Red
            break
        
        }
        
        else {
        
            if ($OS -eq '' -or $null -eq $OS) {
        
                Write-Host 'No OS parameter specified, please provide an OS. Supported value are Android,iOS,WIP_WE,WIP_MDM...' -f Red
                Write-Host
                break
        
            }
        
            elseif ($OS -eq 'Android') {
        
                $Resource = "deviceAppManagement/androidManagedAppProtections('$id')/?`$expand=deploymentSummary,apps,assignments"
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        
            }
        
            elseif ($OS -eq 'iOS') {
        
                $Resource = "deviceAppManagement/iosManagedAppProtections('$id')/?`$expand=deploymentSummary,apps,assignments"
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        
            }
    
            elseif ($OS -eq 'WIP_WE') {
        
                $Resource = "deviceAppManagement/windowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
        
            }
    
            elseif ($OS -eq 'WIP_MDM') {
        
                $Resource = "deviceAppManagement/mdmWindowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
            }
        
        }
        
    }
    
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
        
    }
    
}
Function Get-ManagedAppPolicy() {

    <#
    .SYNOPSIS
    This function is used to get managed app policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app policies
    .EXAMPLE
    Get-ManagedAppPolicy
    Returns any managed app policies configured in Intune
    .NOTES
    NAME: Get-ManagedAppPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $Name
    )
    
    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/managedAppPolicies'
    
    try {
        
        if ($Name) {
        
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }
            Write-Host -ForegroundColor Cyan "$Name App Protection Policy Found"
        }
        
        else {
        
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains('ManagedAppProtection') -or ($_.'@odata.type').contains('InformationProtectionPolicy') }
        
        }
        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
        
    }
        
}
Function Get-ManagedAppAppConfigPolicy() {

    <#
        .SYNOPSIS
        This function is used to get app configuration policies for managed apps from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any app configuration policy for managed apps
        .EXAMPLE
        Get-ManagedAppAppConfigPolicy
        Returns any app configuration policy for managed apps configured in Intune
        .NOTES
        NAME: Get-ManagedAppAppConfigPolicy
        #>
        
    $graphApiVersion = 'Beta'
    $Resource = "deviceAppManagement/targetedManagedAppConfigurations?`$expand=apps"
            
    try {
                
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value 
                
    }
            
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
        
    }
        
}
Function Get-ManagedDeviceAppConfigPolicy() {
        
    <#
        .SYNOPSIS
        This function is used to get app configuration policies for managed devices from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any app configuration policy for managed devices
        .EXAMPLE
        Get-ManagedDeviceAppConfigPolicy
        Returns any app configuration policy for managed devices configured in Intune
        .NOTES
        NAME: Get-ManagedDeviceAppConfigPolicy
        #>
        
    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'
        
    try {
                
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value 
                
    }
            
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
        
    }
        
}
Function Get-IntuneFilter() {

    <#
    .SYNOPSIS
    This function is used to get all filters configured from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any filters created
    .EXAMPLE
    Get-IntuneFilter
    Returns any Filters configured in Intune
    .NOTES
    NAME: Get-IntuneFilter
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/assignmentFilters'
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Get-DeviceCompliancePolicy() {

    <#
    .SYNOPSIS
    This function is used to get device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies
    .EXAMPLE
    Get-DeviceCompliancePolicy
    Returns any device compliance policies configured in Intune
    .EXAMPLE
    Get-DeviceCompliancePolicy -Android
    Returns any device compliance policies for Android configured in Intune
    .EXAMPLE
    Get-DeviceCompliancePolicy -iOS
    Returns any device compliance policies for iOS configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    
  
    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Get-DeviceConfigurationPolicy() {

    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = 'beta'
    $DCP_resource = 'deviceManagement/deviceConfigurations'
    
    try {
    
        if ($Name) {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=displayName eq '$name'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Get-SoftwareUpdatePolicy() {

    <#
    .SYNOPSIS
    This function is used to get Software Update policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Software Update policies
    .EXAMPLE
    Get-SoftwareUpdatePolicy -Windows10
    Returns Windows 10 Software Update policies configured in Intune
    .EXAMPLE
    Get-SoftwareUpdatePolicy -iOS
    Returns iOS update policies configured in Intune
    .NOTES
    NAME: Get-SoftwareUpdatePolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        [switch]$Windows10,
        [switch]$iOS
    )
    
    $graphApiVersion = 'Beta'
    
    try {
    
        $Count_Params = 0
    
        if ($iOS.IsPresent) { $Count_Params++ }
        if ($Windows10.IsPresent) { $Count_Params++ }
    
        if ($Count_Params -gt 1) {
    
            Write-Host 'Multiple parameters set, specify a single parameter -iOS or -Windows10 against the function' -f Red
    
        }
    
        elseif ($Count_Params -eq 0) {
    
            Write-Host 'Parameter -iOS or -Windows10 required against the function...' -ForegroundColor Red
            Write-Host
            break
    
        }
    
        elseif ($Windows10) {
    
            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value
    
        }
    
        elseif ($iOS) {
    
            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.iosUpdateConfiguration')&`$expand=groupAssignments"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Get-SettingsCatalogPolicy() {

    <#
    .SYNOPSIS
    This function is used to get Settings Catalog policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Settings Catalog policies
    .EXAMPLE
    Get-SettingsCatalogPolicy
    Returns any Settings Catalog policies configured in Intune
    Get-SettingsCatalogPolicy -Platform windows10
    Returns any Windows 10 Settings Catalog policies configured in Intune
    Get-SettingsCatalogPolicy -Platform macOS
    Returns any MacOS Settings Catalog policies configured in Intune
    .NOTES
    NAME: Get-SettingsCatalogPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        [parameter(Mandatory = $false)]
        [ValidateSet('windows10', 'macOS')]
        [ValidateNotNullOrEmpty()]
        [string]$Platform
    )
    
    $graphApiVersion = 'beta'
    
    if ($Platform) {
            
        $Resource = "deviceManagement/configurationPolicies?`$filter=platforms has '$Platform' and technologies has 'mdm'"
    
    }
    
    else {
    
        $Resource = "deviceManagement/configurationPolicies?`$filter=technologies has 'mdm'"
    
    }
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Get-EndpointSecurityPolicy() {

    <#
    .SYNOPSIS
    This function is used to get all Endpoint Security policies using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets all Endpoint Security templates
    .EXAMPLE
    Get-EndpointSecurityPolicy
    Gets all Endpoint Security Policies in Endpoint Manager
    .NOTES
    NAME: Get-EndpointSecurityPolicy
    #>
    
    
    $graphApiVersion = 'Beta'
    $ESP_resource = 'deviceManagement/intents'
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
            (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value
    
    }
        
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Get-DeviceManagementScripts() {

    <#
    .SYNOPSIS
    This function is used to get device management scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device management scripts
    .EXAMPLE
    Get-DeviceManagementScripts
    Returns any device management scripts configured in Intune
    Get-DeviceManagementScripts -ScriptId $ScriptId
    Returns a device management script configured in Intune
    .NOTES
    NAME: Get-DeviceManagementScripts
    #>
    
    [cmdletbinding()]
    
    param (
    
        [Parameter(Mandatory = $false)]
        $ScriptId
    
    )
    
    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceManagementScripts'
        
    try {
    
        if ($ScriptId) {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$ScriptId"
    
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$expand=groupAssignments"
            (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).Value
    
        }
        
    }
        
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Remove-ManagedAppPolicy() {

    <#
    .SYNOPSIS
    This function is used to remove Managed App policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes managed app policies
    .EXAMPLE
    Remove-ManagedAppPolicy -id $id
    Removes a managed app policy configured in Intune
    .NOTES
    NAME: Remove-ManagedAppPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/managedAppPolicies'
    
    try {
    
        if ($id -eq '' -or $null -eq $id) {
    
            Write-Host "No id specified for managed app policy, can't remove managed app policy..." -f Red
            Write-Host 'Please specify id for managed app policy...' -f Red
            break
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
    
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Remove-ManagedAppAppConfigPolicy() {

    <#
    .SYNOPSIS
    This function is used to remove Managed App policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes managed app policies
    .EXAMPLE
    Remove-ManagedAppAppConfigPolicy -id $id
    Removes a managed app policy configured in Intune
    .NOTES
    NAME: Remove-ManagedAppAppConfigPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/targetedManagedAppConfigurations'
    
    try {
    
        if ($id -eq '' -or $null -eq $id) {
    
            Write-Host "No id specified for managed app policy, can't remove managed app policy..." -f Red
            Write-Host 'Please specify id for managed app policy...' -f Red
            break
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
    
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Remove-ManagedDeviceAppConfigPolicy() {

    <#
    .SYNOPSIS
    This function is used to remove Managed App policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes managed app policies
    .EXAMPLE
    Remove-ManagedDeviceAppConfigPolicy -id $id
    Removes a managed app policy configured in Intune
    .NOTES
    NAME: Remove-ManagedDeviceAppConfigPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = 'Beta'
    $Resource = 'deviceAppManagement/mobileAppConfigurations'
    
    try {
    
        if ($id -eq '' -or $null -eq $id) {
    
            Write-Host "No id specified for managed app policy, can't remove managed app policy..." -f Red
            Write-Host 'Please specify id for managed app policy...' -f Red
            break
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
    
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Remove-DeviceCompliancePolicy() {

    <#
        .SYNOPSIS
        This function is used to delete a device configuration policy from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and deletes a device compliance policy
        .EXAMPLE
        Remove-DeviceConfigurationPolicy -id $id
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Remove-DeviceConfigurationPolicy
        #>
        
    [cmdletbinding()]
        
    param
    (
        $id
    )
        
    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/deviceCompliancePolicies'
        
    try {
        
        if ($id -eq '' -or $null -eq $id) {
        
            Write-Host "No id specified for device compliance, can't remove compliance policy..." -f Red
            Write-Host 'Please specify id for device compliance policy...' -f Red
            break
        
        }
        
        else {
        
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
            Write-Host "Removed Compliance Policy ID:$id" -f Green
            Write-Host
        }
        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
        
    }
        
}    
Function Remove-DeviceConfigurationPolicy() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-DeviceConfigurationPolicy -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = 'Beta'
    $DCP_resource = 'deviceManagement/deviceConfigurations'
    
    try {
    
        if ($id -eq '' -or $null -eq $id) {
    
            Write-Host "No id specified for device configuration, can't remove configuration..." -f Red
            Write-Host 'Please specify id for device configuration...' -f Red
            break
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
            Write-Host "Removed Configuration Profile ID:$id" -f Green
            Write-Host
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Remove-SettingsCatalog() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-SettingsCatalog -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-SettingsCatalog
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = 'Beta'
    $DCP_resource = 'deviceManagement/configurationPolicies'
    
    try {
    
        if ($id -eq '' -or $null -eq $id) {
    
            Write-Host "No id specified for device configuration, can't remove configuration..." -f Red
            Write-Host 'Please specify id for device configuration...' -f Red
            break
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
            Write-Host "Removed Settings Catalog Profile ID:$id" -f Green
            Write-Host
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Remove-DeviceManagementScripts() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-DeviceManagementScripts -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-DeviceManagementScripts
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = 'Beta'
    $DCP_resource = 'deviceManagement/deviceManagementScripts'
    
    try {
    
        if ($id -eq '' -or $null -eq $id) {
    
            Write-Host "No id specified for device configuration, can't remove configuration..." -f Red
            Write-Host 'Please specify id for device configuration...' -f Red
            break
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
            Write-Host "Removed Device Script ID:$id" -f Green
            Write-Host
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
Function Remove-IntuneFilter() {

    <#
    .SYNOPSIS
    This function is used to remove a device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and removes a device configuration policies
    .EXAMPLE
    Remove-IntuneFilter -id $id
    Removes a device configuration policies configured in Intune
    .NOTES
    NAME: Remove-IntuneFilter
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = 'Beta'
    $DCP_resource = 'deviceManagement/assignmentFilters'
    
    try {
    
        if ($id -eq '' -or $null -eq $id) {
    
            Write-Host "No id specified for device configuration, can't remove configuration..." -f Red
            Write-Host 'Please specify id for device configuration...' -f Red
            break
    
        }
    
        else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
            Write-Host "Removed Device Filter ID:$id" -f Green
            Write-Host

        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    
    }
    
}
#endregion

#region Authentication
# Checking if authToken exists before running authentication
if ($global:authToken) {

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

    if ($TokenExpires -le 0) {

        Write-Host 'Authentication Token expired' $TokenExpires 'minutes ago' -ForegroundColor Yellow
        Write-Host

        # Defining User Principal Name if not present

        if ($null -eq $User -or $User -eq '') {

            $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
            Write-Host

        }

        $global:authToken = Get-AuthToken -User $User

    }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if ($null -eq $User -or $User -eq '') {

        $User = Read-Host -Prompt 'Please specify your user principal name for Azure Authentication'
        Write-Host

    }

    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
    Write-Host 'Connected to Graph API' -ForegroundColor Green
    Write-Host
}

#endregion
$userUpn = New-Object 'System.Net.Mail.MailAddress' -ArgumentList $User
    
if ($userUpn.Host -like '*onmicrosoft.com*') {
    $tenant = Read-Host -Prompt 'Please specify your Tenant name i.e. company.com'
    Write-Host
}
else {
    $tenant = $userUpn.Host
}


Write-Host 'THIS SCRIPT IS DESTRUCTIVE WITH NO RECOVERY' -f Red
Write-Host 'PLEASE REVIEW THE BELOW BEFORE CONTINUING' -f Red
Write-Host 'IF ANY OF THESE SETTINGS ARE INCORRECT ABORT THE SCRIPT' -f Red
Write-Host
Write-Host "User Account: $user" -ForegroundColor Cyan
Write-Host "Azure AD Tenant: $tenant" -ForegroundColor Cyan
Write-Host
Write-Warning 'CONFIRM THE SETTINGS ARE CORRECT BEFORE CONTINUING' -WarningAction Inquire

Write-Host 'STARTING DELETION OF ENDPOINT MANAGER SETTINGS' -f Yellow
Write-Host
Get-ManagedAppPolicy | ForEach-Object {
    Remove-ManagedAppPolicy -id $_.Id
}

Get-DeviceCompliancePolicy | ForEach-Object {
    Remove-DeviceCompliancePolicy -id $_.Id
}

Get-DeviceConfigurationPolicy | ForEach-Object {
    Remove-DeviceConfigurationPolicy -id $_.id
}

Get-SettingsCatalogPolicy | ForEach-Object {
    Remove-SettingsCatalog -id $_.id
}

Get-IntuneFilter | ForEach-Object {
    Remove-IntuneFilter -id $_.id
}

Get-DeviceManagementScripts | ForEach-Object {
    Remove-DeviceManagementScripts -id $_.id
}

Get-ManagedAppAppConfigPolicy | ForEach-Object {
    Remove-ManagedAppAppConfigPolicy -id $_.id
}

Get-ManagedDeviceAppConfigPolicy | ForEach-Object {
    Remove-ManagedDeviceAppConfigPolicy -id $_.id
}
Write-Host 'DELETION OF ENDPOINT MANAGER SETTINGS COMPLETE' -f Green
Write-Host
Write-Host 'PLEASE REVIEW ANY ERRORS AND PERFORM MANUAL CLEAN UP WHERE REQUIRED' -f Yellow