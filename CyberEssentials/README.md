# SYNOPSIS
This script is used to apply a default set of Compliance Policies, Device Filters and Conditional Access Policies for use with Cyber Security Essentials compliance.

# DESCRIPTION
Using the Intune PowerShell examples and custom PowerShell functions to import Compliance Policies, Device Filters and Conditional Access Policies from exported JSON files into Microsoft Endpoint Manager user Graph API.

Using each of the script parameters, you can configure which operating systems are configured as well as whether the Compliance Policies are for Corporate, BYOD, or Both enrolment types.

Using the `Assign` parameter, you can instruct the script to assign each of the Compliance Policies to the `All Users` group using a corresponding Device Filter, otherwise no assignments are made.

Using the `ConditionalAccess` parameter, you can instruct the script to import the Conditional Access Policies.

# EXAMPLES
```PowerShell
Set-MEMCyberEssentials.ps1 -Windows Corporate -Android Both -iOS BYOD -Assign $True -ConditionalAccess $False

Set-MEMCyberEssentials.ps1 -Windows Corporate -Android Corporate -iOS Corporate -macOS BYOD -Assign $False -ConditionalAccess $True

```