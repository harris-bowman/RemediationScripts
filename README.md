## Detect-AOVPNDeviceTunelIPv4Metric.ps1
Detects the AOVPN Device tunel installed on the system is set to a chosen IPv4 Interface metric by looking at %programdata%\Microsoft\Network\Connections\Pbk\rasphone.pbk

## Detect-AOVPNUserTunelIPv4Metric.ps1
Detects the AOVPN User tunel installed on the system is set to a chosen IPv4 Interface metric by looking at %appdata%\Microsoft\Network\Connections\Pbk\rasphone.pbk

## Detect-PublicDNSAddressesOnNIC.ps1
Detects if there are Public DNS servers configured on the system at HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces "NameServer"
Specifically IPs that match: 
- "*1.1.\*"
- "*8.8.\*"
- "*192.168.\*"
- "*208.67.\*"
- "*9.9.\*"
- "*149.112.\*"

## Detect-UninstallClassicTeams-Improved.ps1
An imporved detection for the Classic Teams application. 

## Detect_SecureBootKeysStatus.ps1
Checks and outputs the servicing status of the Secure Boot Servicing registry to track the deployment of the new 2023 Secure Boot Certificates. 

Outputs status to the Detection script output, and only returns "No remediation needed" or Exit 0 when UEFICA2023Status = "Updated"

No remediation script as this is simpily a Detection script to be used as a Report/Tracker.

Reference: https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d#bkmk_how_keys_work_together

## Detect_SecureBootRegKeys.ps1
Detects the Secure Boot Settings to signal Windows to execute the Secure Boot key update and installation on the device.
Settings Detected in this script:
Path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot

| Key | Detection Value | Description |
| --- | --- | --- |
| AvailableUpdates | Exists & Does not = 0 | Controls which Secure Boot update actions to perform on the device. Setting the appropriate bitfield here initiates the deployment of new Secure Boot certificates and related updates. For enterprise deployment, this should be set to 0x5944 (hex) – a value that enables all relevant updates (adding the new 2023 CA certificates, updating the KEK, and installing the new boot manager). |
| HighConfidenceOptOut | DWORD: 0 | An opt out option. For enterprises that want to opt out of high confidence buckets that will automatically be applied as part of the LCU. |
| MicrosoftUpdateManagedOptIn | DWORD: 1 | An opt in option. For enterprises that want to opt-in to Controlled Feature Rollout (CFR) servicing, also known as Microsoft Managed. |

## Remediate-AOVPNDeviceTunelIPv4Metric.ps1
Sets the AOVPN Device tunel installed on the system to a chosen IPv4 Interface metric by editing %programdata%\Microsoft\Network\Connections\Pbk\rasphone.pbk

## Remediate-AOVPNUserTunelIPv4Metric.ps1
Sets the AOVPN User tunel installed on the system to a chosen IPv4 Interface metric by editing %programdata%\Microsoft\Network\Connections\Pbk\rasphone.pbk

## Remediate-PublicDNSAddressesOnNIC.ps1
Clears HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces "NameServer" - So the systems DNS servers are left up to the NIC, ie. DHCP option configuring.

## Remediate-UninstallClassicTeams-Improved.ps1
An imporved removal script for the Classic Teams application. 

## Remediate_SecureBootRegKeys.ps1
Applied the Secure Boot Settings to signal Windows to execute the Secure Boot key update and installation on the device.
Settings Applied in this script:
Path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot

| Key | Set to Value | Description |
| --- | --- | --- |
| AvailableUpdates | IF it exists & is not 0 = 0x5944 | Controls which Secure Boot update actions to perform on the device. Setting the appropriate bitfield here initiates the deployment of new Secure Boot certificates and related updates. For enterprise deployment, this should be set to 0x5944 (hex) – a value that enables all relevant updates (adding the new 2023 CA certificates, updating the KEK, and installing the new boot manager). |
| HighConfidenceOptOut | DWORD: 0 | An opt out option. For enterprises that want to opt out of high confidence buckets that will automatically be applied as part of the LCU. |
| MicrosoftUpdateManagedOptIn | DWORD: 1 | An opt in option. For enterprises that want to opt-in to Controlled Feature Rollout (CFR) servicing, also known as Microsoft Managed. |
