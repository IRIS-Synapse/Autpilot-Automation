<#
.SYNOPSIS
Retrieves Windows Autopilot devices and sends data to Log Analytics.

.DESCRIPTION
This runbook authenticates to Microsoft Graph API using a service principal,
retrieves Windows Autopilot device identities, and sends the data to Log Analytics workspace.
#>

param()

# Import Az.Accounts module
Import-Module Az.Accounts

# Retrieve variables and credentials from Automation Account
$WorkspaceId = Get-AutomationVariable -Name 'WorkspaceId'
$TenantId = Get-AutomationVariable -Name 'TenantId'
$ClientId = Get-AutomationVariable -Name 'ClientId'
$WorkspaceKey = (Get-AutomationPSCredential -Name 'WorkspaceKey').Password
$ClientSecret = (Get-AutomationPSCredential -Name 'ClientSecret').Password

# Authenticate to Microsoft Graph API
$Body = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $ClientId
    Client_Secret = $ClientSecret
}

$TokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $Body
$AccessToken = $TokenResponse.access_token

# Retrieve Autopilot devices
$Headers = @{
    Authorization = "Bearer $AccessToken"
}

$AutopilotDevices = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities" -Headers $Headers -ErrorAction Stop

# Prepare data for Log Analytics
$Data = $AutopilotDevices.value | ForEach-Object {
    [PSCustomObject]@{
        DeviceId                    = $_.id
        DeviceSerialNumber          = $_.serialNumber
        DeviceName                  = $_.displayName
        AssignedProfileId           = $_.deploymentProfileId
        AssignedUserPrincipalName   = $_.userPrincipalName
        LastModifiedDateTime        = $_.lastModifiedDateTime
    }
}

$JsonData = $Data | ConvertTo-Json -Depth 10

# Create the signature for the Log Analytics request
$TimeStamp = Get-Date -Format "r"
$ContentLength = $JsonData.Length
$StringToSign = "POST\n$ContentLength\napplication/json\nx-ms-date:$TimeStamp\n/api/logs"
$BytesToSign = [Text.Encoding]::UTF8.GetBytes($StringToSign)
$HMACKey = [Convert]::FromBase64String($WorkspaceKey)
$HashedSignature = [System.Security.Cryptography.HMACSHA256]::New($HMACKey).ComputeHash($BytesToSign)
$Signature = [Convert]::ToBase64String($HashedSignature)
$Authorization = "SharedKey ${WorkspaceId}:${Signature}"


# Send data to Log Analytics
$LogAnalyticsUri = "https://$($WorkspaceId).ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

$LogHeaders = @{
    "Content-Type"        = "application/json"
    "Authorization"       = $Authorization
    "Log-Type"            = "AutopilotDevices"
    "x-ms-date"           = $TimeStamp
    "time-generated-field" = "LastModifiedDateTime"
}

Invoke-RestMethod -Method Post -Uri $LogAnalyticsUri -Headers $LogHeaders -Body $JsonData -ErrorAction Stop
