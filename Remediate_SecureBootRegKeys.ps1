<#
.SYNOPSIS
    PowerShell script to apply the settings and trigger the UEFI 2023 CA certificate update process for SecureBoot on Windows devices.
.DESCRIPTION
    This PowerShell script is deployed as a remediation script using Remediations in Microsoft Endpoint Manager/Intune. It will set the following, and Exit 0 if all are completed successfully:
    - The SecureBoot registry path is created if it doesn't exist.
    - The HighConfidenceOptOut value is set to 0
    - The MicrosoftUpdateManagedOptIn value is set to 1.
    - The AvailableUpdates value:
        -If it doesn't exist, set to 0x5944.
        -If it exists and is set to 0, set to 0x5944.
        -If it exists and is not set to 0, leave it alone as this suggests the update is already in progress or has completed, and we don't want to interfere with that.

    The Detection script to pair with this is: https://github.com/harris-bowman/RemediationScripts/blob/main/Detect_SecureBootRegKeys.ps1
.LINK
    https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#bkmk_how_keys_work_together
    https://docs.microsoft.com/en-us/mem/analytics/proactive-remediations
.NOTES
    Version:        1.3
    Creation Date:  2026-01-28
    Last Updated:   2026-02-10
    Author:         Harris Bowman
    Repository:     https://github.com/harris-bowman/RemediationScripts
    Requires Local Admin Privileges: Yes
#>

$Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\'
$log = ""
$value = $null

#Safeguard if certificates are already installed:
if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue).UEFICA2023Status -eq "Updated"-and (([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'))) {
    Write-Host "SecureBoot updates already installed successfully. No remediation needed."
    exit 0
}

#Check the registry key SecureBoot exists.
if (!(Test-Path $Path)) {
    New-Item -Path $Path -Force
    $log += "SecureBoot registry path created. "
}
$keyItem = Get-Item -Path $Path

$value = $keyItem.GetValue('HighConfidenceOptOut', $null)
if ($null -eq $value) {
    #If HighConfidenceOptOut doesn't exist, create it and set to 0.
    New-ItemProperty -Path $Path -Name 'HighConfidenceOptOut' -PropertyType DWord -Value 0 -Force
} elseif ($value -ne 0) {
    #If HighConfidenceOptOut exists but is not set to 0, set it to 0.
    Set-ItemProperty -Path $Path -Name 'HighConfidenceOptOut' -Value 0 -Force
    $log += "Configured HighConfidenceOptOut to 0. "
}   

$value = $keyItem.GetValue('MicrosoftUpdateManagedOptIn', $null)
if ($null -eq $value) {
    #If MicrosoftUpdateManagedOptIn doesn't exist, create it and set to 1.
    New-ItemProperty -Path $Path -Name 'MicrosoftUpdateManagedOptIn' -PropertyType DWord -Value 1 -Force
} elseif ($value -ne 1) {
    #If MicrosoftUpdateManagedOptIn exists but is not set to 1, set it to 1.
    Set-ItemProperty -Path $Path -Name 'MicrosoftUpdateManagedOptIn' -Value 1 -Force
    $log += "Configured MicrosoftUpdateManagedOptIn to 1. "
}   

$val = $keyItem.GetValue('AvailableUpdates', $null)
if ($null -eq $val) {
    #If AvailableUpdates doesn't exist, create it and set to 0x5944.
    New-ItemProperty -Path $Path -Name 'AvailableUpdates' -PropertyType DWord -Value 0x5944 -Force
    $log += "Configured AvailableUpdates to 0x5944 (key didn't exist.). "
    #Start the Scheduled Task to kick off the update process.
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update" -ErrorAction SilentlyContinue
    $log += "Attempted to start Scheduled Task. "
} elseif (0 -eq $val) {
    #If AvailableUpdates exists but is set to 0, set it to 0x5944.
    Set-ItemProperty -Path $Path -Name 'AvailableUpdates' -Value 0x5944 -Force
    $log += "Configured AvailableUpdates to 0x5944 (was 0). "
    #Start the Scheduled Task to kick off the update process.
    Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update" -ErrorAction SilentlyContinue
    $log += "Attempted to start Scheduled Task. "
} else {
    #If AvailableUpdates exists but is not set to 0, leave it alone as this suggests the update is already in progress or has completed, and we don't want to interfere with that.
    $valHex = ('0x{0:X}' -f $val)
    $log += "AvailableUpdates present but set to $valHex, Leaving alone. "
}

$log = "SecureBoot registry keys configured successfully: " + $log
Write-Host $log
exit 0