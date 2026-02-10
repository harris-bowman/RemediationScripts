<#
.SYNOPSIS
    PowerShell script to detect the settings needed to trigger the UEFI 2023 CA certificate update process for SecureBoot on Windows devices.
.DESCRIPTION
    This PowerShell script is deployed as a detection script using Remediations in Microsoft Endpoint Manager/Intune. It will Exit 1 (Remediation Needed) if any of the following are true:
    - The SecureBoot registry path doesn't exist. 
    - The HighConfidenceOptOut value is not set to 0.
    - The MicrosoftUpdateManagedOptIn value is not set to 1.
    - The AvailableUpdates value doesn't exist or is set to 0.

    The Remediation script to pair with this is: https://github.com/harris-bowman/RemediationScripts/blob/main/Remediate_SecureBootRegKeys.ps1
.LINK
    https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#bkmk_how_keys_work_together
    https://docs.microsoft.com/en-us/mem/analytics/proactive-remediations
.NOTES
    Version:        1.2
    Creation Date:  2026-01-28
    Last Updated:   2026-02-10
    Author:         Harris Bowman
    Repository:     https://github.com/harris-bowman/RemediationScripts
    Requires Local Admin Privileges: Yes
#>

$Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\'
$log = ""
$fail = $false

#Safeguard if certificates are already installed.
if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue).UEFICA2023Status -eq "Updated"-and (([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'))) {
    Write-Host "SecureBoot updates already installed successfully. No remediation needed."
    exit 0
}

#Check the registry key SecureBoot exists.
if (!(Test-Path $Path)) {
    $log += "SecureBoot registry path not found. " 
    $fail = $true
} 

#Check if HighConfidenceOptOut is not set to 0.
if ((Get-ItemProperty -Path $Path -Name 'HighConfidenceOptOut' -ErrorAction SilentlyContinue).HighConfidenceOptOut -ne 0) {
    $log += "HighConfidenceOptOut is not set to 0. "
    $fail = $true
}

##Check if MicrosoftUpdateManagedOptIn is not set to 1.
if ((Get-ItemProperty -Path $Path -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn -ne 1) {
    $log += "MicrosoftUpdateManagedOptIn is not set to 1. "
    $fail = $true
}

#Check if AvailableUpdates doesn't exist or is set to 0.
$value = Get-ItemPropertyValue -Path $Path -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
if ($null -eq $value) {
        $log += "AvailableUpdates is not set."
        $fail = $true
} elseif ($value -eq 0) {
        $log += "AvailableUpdates is set to 0. "
        $fail = $true
}

#If any of the above checks have set $fail to true: Remediation is needed, we Write-Host $log to send the report back to Intune Remediations and Exit 1. 
#If not, we Write-Host the current key values to send the report back to Intune Remediations and Exit 0. 
if ($fail) {
    $log = "Remediation Needed: " + $log
    Write-Host $log
    exit 1 
} else {
    $hkOO = (Get-ItemProperty -Path $Path -Name 'HighConfidenceOptOut' -ErrorAction SilentlyContinue).HighConfidenceOptOut
    $mkMUI = (Get-ItemProperty -Path $Path -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn
    $auKey = (Get-ItemProperty -Path $Path -Name 'AvailableUpdates' -ErrorAction SilentlyContinue).AvailableUpdates
    $auKeyvalHex = ('0x{0:X}' -f $auKey)
    Write-Host "All SecureBoot registry keys are correctly configured: HighConfidenceOptOut: $hkOO MicrosoftUpdateManagedOptIn: $mkMUI AvailableUpdates: $auKeyvalHex"
    exit 0
}
