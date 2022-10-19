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
    
    $tenant = $userUpn.Host
    
    Write-Host 'Checking for AzureAD module...'
    
    $AadModule = Get-Module -Name 'AzureAD' -ListAvailable
    
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
            Write-Host
            Write-Host 'Successfully authenticated to Graph API...' -ForegroundColor Green
            Write-Host
    
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
Function Import-PowerShellModules {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ModuleName
    )
    Write-Host "Checking for $ModuleName module..." -f Yellow
    Write-Host
    $Module = Get-Module -Name $ModuleName -ListAvailable
    if ($null -eq $Module) {
        Try {
            Write-Host "$ModuleName PowerShell module not found, installing module..." -f Yellow
            Write-Host
            Install-Module -Name $ModuleName -Force
            Write-Host "$ModuleName installed" -f Green
            Write-Host
        }
        Catch {
            Write-Host "Unable to install $ModuleName PowerShell module" -f Red
            Write-Host "Script can't continue..." -f Red
            Write-Host
            break
        }
    }
    else {
        Try {
            Write-Host "Importing $ModuleName PowerShell module..." -f yellow
            Write-Host
            Import-Module -Name $ModuleName
            Write-Host "$ModuleName PowerShell module imported" -f Green
            Write-Host
        }
        Catch {
            Write-Host "Unable to import $ModuleName PowerShell module..." -f Red
            Write-Host "Script can't continue..." -f Red
            Write-Host
            break
        }
    }
    

}
Function Get-MEMGroup() {

    [cmdletbinding()]
    
    param
    (
        [string]$GroupName
    )

    # Defining Variables
    $graphApiVersion = 'v1.0'
    $Resource = 'groups'
    
    try {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=displayName eq '$GroupName'"

    
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
Function Set-MEMGroup() {

    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Dynamic', 'Assigned')]
        [string]$Type,
        [Parameter(Mandatory = $true)]
        [boolean]$Security,
        [Parameter(Mandatory = $true)]
        [boolean]$Mail,
        [string]$Rule

    )

    # Defining Variables
    $graphApiVersion = 'beta'
    $Resource = 'groups'

    $MailName = $Name -replace '\s', ''
    $Output = New-Object -TypeName psobject
    $Output | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description
    $Output | Add-Member -MemberType NoteProperty -Name 'displayName' -Value $Name

    if ($Type -eq 'Dynamic') {
        $Output | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @('DynamicMembership')
        if (!$Rule) {
            Write-Host 'No Dynamic Membership rule found' -ForegroundColor Red
            Break
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name 'membershipRule' -Value $Rule
            $Output | Add-Member -MemberType NoteProperty -Name 'membershipRuleProcessingState' -Value 'On'
        }
    }
    elseif ($Type -eq 'Assigned') {
        $Output | Add-Member -MemberType NoteProperty -Name 'groupTypes' -Value @()
    }
    
    $Output | Add-Member -MemberType NoteProperty -Name 'mailEnabled' -Value $Mail
    $Output | Add-Member -MemberType NoteProperty -Name 'mailNickname' -Value $MailName
    $Output | Add-Member -MemberType NoteProperty -Name 'securityEnabled' -Value $Security

    $JSON = $Output | ConvertTo-Json -Depth 5

    try {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON
        
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

#region Script
$Sleep = '5'

Write-Host '************************************************************************************'
Write-Host '****                                                                            ****'
Write-Host '****    Welcome to the Endpoint Manager Accelerator Script                      ****' -ForegroundColor Green
Write-Host '****    This Script will implement a known good Endpoint Manager baseline       ****' -ForegroundColor Cyan
Write-Host '****    for Windows, iOS/iPadOS and Android devices.                            ****' -ForegroundColor Cyan
Write-Host '****                                                                            ****'
Write-Host '************************************************************************************'
Write-Host
Write-Host 'Please Choose one of the implementation options below: ' -ForegroundColor Yellow
Write-Host
Write-Host '(0) Backup environment only... ' -ForegroundColor Green
Write-Host
Write-Host '(1) Proof-of-Concept implementation... ' -ForegroundColor Green
Write-Host
Write-Host '(2) Restore customer environment from backup... ' -ForegroundColor Green
Write-Host
Write-Host '(E) EXIT SCRIPT ' -ForegroundColor Red
Write-Host
$Choice_Number = ''
$Choice_Number = Read-Host -Prompt 'Based on which option you want to run, please type 1, 2, or E to exit the script, then hit enter ' 
while ( !($Choice_Number -eq '0' -or $Choice_Number -eq '1' -or $Choice_Number -eq '2' -or $Choice_Number -eq 'E')) {
    $Choice_Number = Read-Host -Prompt 'Invalid Option, Based on which option you want to run, please type 0, 1, 2, or E to exit the script, then hit enter ' 
}
if ($Choice_Number -eq 'E') { 
    Break
}
if ($Choice_Number -eq '0') { 
    $Deployment = 'Backup'
    Write-Host
    Write-Host 'Backup Only selected: existing environment will be backed up.' -ForegroundColor Yellow
    Write-Host
}
if ($Choice_Number -eq '1') { 
    $Deployment = 'POC'
    Write-Host
    Write-Host 'Proof-of-Concept Implementation selected: settings will be assigned to groups of devices and users.' -ForegroundColor Yellow
    Write-Host
}
if ($Choice_Number -eq '2') { 
    $Deployment = 'Restore'
    Write-Host
    Write-Host 'Customer Endpoint Manager Environment will be restored from a backup.' -ForegroundColor Yellow
    Write-Host  
}

#region PowerShell Modules
Start-Sleep -Seconds $Sleep
Write-Host 'Importing required PowerShell Modules...' -ForegroundColor Yellow
Write-Host
Start-Sleep -Seconds $Sleep
Import-PowerShellModules -ModuleName IntuneBackupAndRestore
Import-PowerShellModules -ModuleName AzureAD
Import-PowerShellModules -ModuleName Microsoft.Graph.Intune
#endregion

#region Authentication
Start-Sleep -Seconds $Sleep
Write-Host 'Authenticating to Graph API...' -ForegroundColor Yellow
Write-Host
Write-Host 'Ensure you have a Global Administrator account for the customer environment...' -ForegroundColor Cyan
Write-Host
Start-Sleep -Seconds $Sleep
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
    
            $User = Read-Host -Prompt 'Please specify your user principal name for Authentication'
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
    
}

Connect-MSGraph | Out-Null

#endregion
#region Variables
$ScriptPath = (Get-Location).Path
$Customer = (New-Object 'System.Net.Mail.MailAddress' -ArgumentList $User).Host
$RestoreFolder = $ScriptPath + '\Restore\'
$GroupFolder = $ScriptPath + '\Groups\'
$BackupFolder = $ScriptPath + '\Backup\' + $Customer + '\' + $(Get-Date -Format yyyy_MM_dd_HHmm)

If (!(Test-Path $BackupFolder)) {
    Write-Host "Creating $BackupFolder" -ForegroundColor Yellow
    Write-Host
    New-Item -ItemType Directory -Force -Path $BackupFolder | Out-Null
    Write-Host "Created $BackupFolder" -ForegroundColor Green
    Write-Host
}
#endregion

#region MEM Backup
Start-Sleep -Seconds $Sleep
Try {
    Write-Host "Starting the backup of $Customer Endpoint Manager configuration to $BackupFolder" -f Yellow
    Write-Host
    # Start-IntuneBackup -Path $BackupFolder | Out-Null
    Write-Host "Backup of $Customer Endpoint Manager configuration to $BackupFolder completed successfully" -f Green
    Write-Host
}
Catch {
    Write-Host 'Unable to backup Endpoint Manager configuration' -f Red
    Write-Host "Script can't continue..." -f Red
    Write-Host
    break
}
if ($Deployment -eq 'Backup') {
    break
}
#endregion

#region Pre-Requisite check
Start-Sleep -Seconds $Sleep
Write-Host
Write-Host "Please review the following areas in the $Customer Endpoint Manager environment before continuing:" -f Yellow
Write-Host
Write-Host " - MDM User Scope set to 'All' or a Group" -ForegroundColor Cyan
Write-Host
Write-Host " - MAM User Scope set 'None'" -ForegroundColor Cyan
Write-Host
Write-Host ' - Managed Google Play is configured' -ForegroundColor Cyan
Write-Host
Write-Host ' - Apple Push Certificate is configured' -ForegroundColor Cyan
Write-Host
Write-Host ' - Apple Enrolment Token and VPP token are configured (if required)' -ForegroundColor Cyan
Write-Host
Write-Host ' - Managed Google Play Apps: Edge, Office, OneDrive for Business, OneNote, Outlook, Teams, SharePoint' -ForegroundColor Cyan
Write-Host
Write-Host ' - iOS Store/VPP Apps: Edge, Office, OneDrive for Business, OneNote, Outlook, Teams, SharePoint' -ForegroundColor Cyan
Write-Host
Write-Warning 'Please confirm the above have been configured before continuing' -WarningAction Inquire
#endregion

#region MEM Restore
Start-Sleep -Seconds $Sleep
Write-Host "Preparing to restore configuration to $Customer Endpoint Manager environment..." -ForegroundColor Yellow
Write-Host
Write-Warning 'Please confirm you are happy to continue the restore operation...' -WarningAction Inquire
Write-Host
Write-Host "Deployment Type: $Deployment" -ForegroundColor Yellow
Write-Host

if ($Deployment -eq 'Restore') {
    $RestoreFolder = Read-Host 'Please specify the folder location you want to restore from...'
}
else {
    $RestoreFolder = $RestoreFolder + $Deployment
}

Try {
    if (!(Test-Path $RestoreFolder)) {
        Write-Host 'Restore Path location does not exist...' -ForegroundColor Red
        Write-Host "Script can't continue..." -ForegroundColor Red
        Write-Host
        break
    }
    Write-Warning "Please confirm you are happy to restore from $RestoreFolder to the $Customer Endpoint Manager environment..." -WarningAction Inquire
    Write-Host
    Write-Host "Starting Endpoint Manager restore with files from $RestoreFolder to the $Customer Endpoint Manager environment..." -ForegroundColor Yellow
    Write-Host
    Start-IntuneRestoreConfig -Path $RestoreFolder
    Write-Host 'Endpoint Manager restore completed successfully.' -ForegroundColor green
    Write-Host
    
}
Catch {
    Write-Host 'Unable to restore Endpoint Manager configuration...' -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break
}
#endregion

#region Group Creation
Start-Sleep -Seconds $Sleep
Write-Host "Preparing to create Azure AD Groups in $Customer Endpoint Manager environment..." -ForegroundColor Yellow
Write-Host
Write-Warning 'Please confirm you are happy to continue the operation...' -WarningAction Inquire
Write-Host

if (!(Test-Path $($GroupFolder + $Deployment + '.csv'))) {
    Write-Host 'Group Path location does not exist...' -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break
}
else {
    $Groups = Import-Csv -Path $($GroupFolder + $Deployment + '.csv')
}

if ($Deployment -eq 'POC') {
    Write-Host 'Creating Proof-of-Concept Azure AD Groups...' -ForegroundColor Yellow
    Write-Host
    foreach ($Group in $Groups) {
        If (!(Get-MEMGroup -GroupName $Group.DisplayName)) {
            Set-MEMGroup -Name $Group.DisplayName -Description $Group.Description -Security $true -Mail $false -Type Assigned
            Write-Host 'Successfully created the group '$Group.DisplayName'...' -ForegroundColor Green
            Write-Host
        }
        Else {
            Write-Host 'The group '$Group.DisplayName' already exists...' -ForegroundColor Cyan
            Write-Host
        }
        
    }
}
elseif ($Deployment -eq 'Production') {
    Write-Host 'Creating Production Azure AD Groups...' -ForegroundColor Yellow
    Write-Host
    foreach ($Group in $Groups) {
        If (!(Get-MEMGroup -GroupName $Group.DisplayName)) {
            Set-MEMGroup -Name $Group.DisplayName -Description $Group.Description -Security $true -Mail $false -type Dynamic -Rule $Group.MembershipRule
            Write-Host 'Successfully created the group '$Group.DisplayName'...' -ForegroundColor Green
            Write-Host
        }
        Else {
            Write-Host 'The group '$Group.DisplayName' already exists...' -ForegroundColor Cyan
            Write-Host
        }
        
    }
}   
Else {
    Write-Host "No AAD groups to be created in $Customer Endpoint Manager environment..." -ForegroundColor Yellow
    Write-Host
}
#endregion

#region Assignment
Start-Sleep -Seconds $Sleep
Write-Host "Preparing to restore assignments to $Customer Endpoint Manager environment..." -ForegroundColor Yellow
Write-Host
Write-Host "Assignments being restored from $RestoreFolder..." -ForegroundColor Yellow
Write-Host
Write-Warning 'Please confirm you are happy to continue the assignment operation...' -WarningAction Inquire
Write-Host
try {
    Write-Host "Starting Assignment restore to $Customer Endpoint Manager environment..." -ForegroundColor Yellow
    Write-Host
    Start-IntuneRestoreAssignments -Path $RestoreFolder
    Write-Host 'Endpoint Manager assignment restore completed successfully.' -ForegroundColor green
    Write-Host
}
catch {
    Write-Host 'Unable to restore Endpoint Manager assignments...' -ForegroundColor Red
    Write-Host "Script can't continue..." -ForegroundColor Red
    Write-Host
    break
}

#endregion
Start-Sleep -Seconds $Sleep
Write-Host "Script completed, please review the implementation of Endpoint Manager in $customer envionment." -ForegroundColor Cyan
Write-Host
#endregion