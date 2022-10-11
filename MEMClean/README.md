# SYNOPSIS
This script is used to remove existing configurations from Microsoft Endpoint Manager.

# DESCRIPTION
Using the Intune PowerShell examples and custom PowerShell functions to get existing configurations in Microsoft Endpoint Manager and remove them, allowing for a clean test tenant for the following areas:

- Managed App Policies
- Compliance Policies
- Configuration Profiles
- Windows Update for Business Rings
- Device Filters
- Device Scripts

Be warned, there may be errors, and confirm which tenant you are connecting to as this script is **destructive**.


# EXAMPLES
```PowerShell
Invoke-MEMClean.ps1

```