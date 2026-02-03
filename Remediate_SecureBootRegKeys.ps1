#reference: https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#bkmk_registry_keys

$Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\'
$log = ""

#Safeguard if certificates are already installed:
if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue).UEFICA2023Status -eq "Updated") {
    Write-Host "SecureBoot updates already installed successfully. No remediation needed."
    exit 0
}

try {

    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force
        $log = $log + "SecureBoot registry path created. "
    }

    New-ItemProperty -Path $Path -Name 'HighConfidenceOptOut' -PropertyType DWord -Value 0 -Force
    $log = $log + "Configured HighConfidenceOptOut to 0. "
    New-ItemProperty -Path $Path -Name 'MicrosoftUpdateManagedOptIn' -PropertyType DWord -Value 1 -Force
    $log = $log + "Configured MicrosoftUpdateManagedOptIn to 1. "

    
    $keyItem = Get-Item -Path $Path
    $val = $keyItem.GetValue('AvailableUpdates', $null)
    if ($null -eq $val) {
        New-ItemProperty -Path $Path -Name 'AvailableUpdates' -PropertyType DWord -Value 0x5944 -Force
        $log = $log + "AvailableUpdates value not present, Configured AvailableUpdates to 0x5944. "
        Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update" -ErrorAction SilentlyContinue
        $log = $log + "Attempted to start Scheduled Task. "
    } else {
        $valHex = ('0x{0:X}' -f $val)
        $log = $log + "AvailableUpdates present but set to $valHex, Leaving alone. "
    }

} catch {
    Write-Host "Error configuring SecureBoot registry keys: $($_.Exception.Message)" + "|" + $log
    exit 1
}
Write-Host "Successfully configured SecureBoot registry keys. " + $log
exit 0