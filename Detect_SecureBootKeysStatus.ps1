<#
.SYNOPSIS
    PowerShell script to detect the status of the UEFI 2023 CA certificate update process for SecureBoot on Windows devices and output the status for reporting in Microsoft Endpoint Manager/Intune Proactive Remediations.
.DESCRIPTION
    This PowerShell script is deployed as a detection script using Remediations in Microsoft Endpoint Manager/Intune.
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

$path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
$log = ""

$keyItem = Get-Item -Path $Path
$UEFICA2023StatusVal = $keyItem.GetValue('UEFICA2023Status', $null)
$UEFICA2023ErrorVal = $keyItem.GetValue('UEFICA2023Error', $null)

$value = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\' -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
if ($null -eq $value) {
    $log += "AvailableUpdates is not set. "
} else {
    $AUKeyHex = ('0x{0:X}' -f $value)
    $log += "AvailableUpdates=$AUKeyHex. "
}

if (!(Test-Path $Path)) {
    Write-Host "SecureBoot Servicing registry not present."
    exit 1
} elseif ($null -eq $UEFICA2023StatusVal) {
    Write-Host "UEFICA2023Status key not present. "
    exit 1
} else {
    
    if ((Get-ItemProperty -Path $path -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue).UEFICA2023Status -eq "NotStarted") {
        $log =+= "The update has not yet run. "
    } elseif ((Get-ItemProperty -Path $path -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue).UEFICA2023Status -eq "InProgress") {
        $log += "The update is actively in progress. "
    } elseif (((Get-ItemProperty -Path $path -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue).UEFICA2023Status -eq "Updated") -and (([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'))) {
        $log += "The update has completed successfully! "
        Write-Host $log
        exit 0
    }

    if ($null -eq $UEFICA2023ErrorVal) {
        $log += "UEFICA2023Error value not present. "
        Write-Host $log
        exit 1
    } elseif ((Get-ItemProperty -Path $path -Name 'UEFICA2023Error' -ErrorAction SilentlyContinue).UEFICA2023Error -ne 0) {
        $errCode = (Get-ItemProperty -Path $path -Name 'UEFICA2023Error' -ErrorAction SilentlyContinue).UEFICA2023Error
        $valHex = ('0x{0:X}' -f $errCode)
        $errCodeEvent = (Get-ItemProperty -Path $path -Name 'UEFICA2023ErrorEvent' -ErrorAction SilentlyContinue).UEFICA2023ErrorEvent
        $valHexEvent = ('0x{0:X}' -f $errCode)
        $log += "Error: $errCode (Hex: $valHex.) - ErrorEvent: $errCodeEvent (Hex: $valHexEvent.) "
        Write-Host $log
        exit 1
    } else {
        Write-Host $log
        exit 1
    }

}