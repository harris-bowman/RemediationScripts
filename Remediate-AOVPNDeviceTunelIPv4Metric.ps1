<#
.SYNOPSIS
    PowerShell script to update the IPv4 Interface Metric value in raspshone.pbk for Always On VPN device tunnel connections.

.EXAMPLE
    .\Remediate-IPv4InterfaceMetric.ps1

.DESCRIPTION
    This PowerShell script is deployed as a remediation script using Proactive Remediations in Microsoft Endpoint Manager/Intune.

.LINK
    https://docs.microsoft.com/en-us/mem/analytics/proactive-remediations

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        1.0
    Creation Date:  2021-10-04
    Last Updated:   2025-12-05
    Author:         Richard Hicks
    Built upon by:  Harris Bowman
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Web Site:       https://directaccess.richardhicks.com/
#>

#######################
## MARK: Variables
$ipv4InterfaceMetric = 4
## This is where you configure the Interface Metric you desire for your AOVPN interface. 
## This script will write this to rasphone.pbk 
## 4 is used in this example as my other script for the user AOVPN tunnel uses 3, which should be a higher priority than the device tunnel.
## 4 is lower than Ethernet interface metrics which are usually 5 or higher.
#######################

$RasphonePath = Join-Path -Path $env:programdata -ChildPath '\Microsoft\Network\Connections\Pbk\rasphone.pbk'
$RasphoneData = Get-Content $RasphonePath

Try {

    Write-Output 'Updating IpInterfaceMetric setting in rasphone.pbk... '
    $newSetting = "IpInterfaceMetric=$ipv4InterfaceMetric"
    $RasphoneData | ForEach-Object { $_ -Replace 'IpInterfaceMetric=.*', $newSetting } | Set-Content -Path $RasphonePath -Force
    Write-Output "Updated. Exit 0"
    Exit 0

}

Catch {

    $ErrorMessage = $_.Exception.Message 
    Write-Output $ErrorMessage
    Exit 1

}