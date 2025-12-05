<#
.SYNOPSIS
    PowerShell script to detect the IPv4 Interface Metric value in raspshone.pbk for Always On VPN device tunnel connections.
.DESCRIPTION
    This PowerShell script is deployed as a detection script using Proactive Remediations in Microsoft Endpoint Manager/Intune.
.LINK
    https://docs.microsoft.com/en-us/mem/analytics/proactive-remediations
.NOTES
    Version:        1.2
    Creation Date:  2025-05-14
    Last Updated:   2025-12-05
    Author:         Harris Bowman
#>

#######################
## MARK: Variables
$ipv4InterfaceMetric = 4
## This is where you configure the Interface Metric you desire for your AOVPN interface. 
## If the script detects anything but this, it will Exit 1 (Remediation Needed)
## 4 is used in this example as my other script for the user AOVPN tunnel uses 3, which should be a higher priority than the device tunnel.
## 4 is lower than Ethernet interface metrics which are usually 5 or higher.
#######################

$RasphonePath = Join-Path -Path $env:programdata -ChildPath '\Microsoft\Network\Connections\Pbk\rasphone.pbk'
$lines = Get-Content -Path $RasphonePath

If ((Test-Path $RasphonePath) -eq $False) {
    Write-Host 'Rasphone.pbk not found. Exit 1 '
    Exit 1
}

try { 
    foreach ($line in $lines) {
        if ($line -match '^\s*IpInterfaceMetric\s*=\s*(\d+)\s*$') {
            $rawValue = $matches[1]
            Write-Host "Raw IpInterfaceMetric match: '$rawValue' "
            $value = $null
            # Try to cast it safely to an integer
            if ([int]::TryParse($rawValue, [ref]$value)) {
                Write-Host "Parsed IpInterfaceMetric: $value "
    
                if ($value -eq $ipv4InterfaceMetric) {
                    Write-Host "IpInterfaceMetric equals $value. Exit 0 "
                    Exit 0
                } else {
                    Write-Host "IpInterfaceMetric equals $value. Exit 1 "
                    Exit 1
                }
            } else {
                Write-Host "Failed to parse IpInterfaceMetric as integer. Got: '$rawValue' Exit 1 "
                Exit 1
            }
    
            $found = $true
            break
        }
    }
    if (-not $found) {
        Write-Host "IpInterfaceMetric setting not found in file. Exit 1 "
        Exit 1
    }
}
catch {
    $ErrorMessage = $_.Exception.Message 
    Write-Host "Error: $ErrorMessage Exit 1" 
    Exit 1
}