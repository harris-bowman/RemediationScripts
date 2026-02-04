#reference: https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#bkmk_registry_keys

$Path  = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\'
$log = ""
$fail = $false

#Safeguard if certificates are already installed:
if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue).UEFICA2023Status -eq "Updated") {
    Write-Host "SecureBoot updates already installed successfully. No remediation needed."
    exit 0
}

if (!(Test-Path $Path)) {
    $log = $log + "SecureBoot registry path not found." 
    $fail = $true
} 

if ((Get-ItemProperty -Path $Path -Name 'HighConfidenceOptOut' -ErrorAction SilentlyContinue).HighConfidenceOptOut -ne 0) {
    $log = $log + " HighConfidenceOptOut is not set to 0. "
    $fail = $true
}

if ((Get-ItemProperty -Path $Path -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn -ne 1) {
    $log = $log + " MicrosoftUpdateManagedOptIn is not set to 1. "
    $fail = $true
}

$value = Get-ItemPropertyValue -Path $Path -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
if ($null -eq $value) {
        $log += " AvailableUpdates is not set."
        $fail = $true
} elseif ($value -eq 0) {
        $log += " AvailableUpdates is set to 0. "
        $fail = $true
}

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
