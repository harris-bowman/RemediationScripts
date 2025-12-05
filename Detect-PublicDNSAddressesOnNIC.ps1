[bool]$remediationNeeded = $false
[String]$global:log = ""
function Write-to-log {
    Param ([string]$LogWriteInput)
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $global:log = $global:log + "`r`n" + $Stamp + " " + $LogWriteInput
 }

# Get all network interfaces from the registry
$interfaces = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

foreach ($interface in $interfaces) {
    
    # Get the DNS server addresses
    $dnsServers = Get-ItemProperty -Path $interface.PSPath -Name "NameServer" -ErrorAction SilentlyContinue

    if ($dnsServers.NameServer -like "*1.1.*" -or $dnsServers.NameServer -like "*8.8.*" -or $dnsServers.NameServer -like "*192.168.*" -or $dnsServers.NameServer -like "*208.67.*" -or $dnsServers.NameServer -like "*9.9.*" -or $dnsServers.NameServer -like "*149.112.*") {
        Write-to-log("Public DNS name servers detected on interface $($interface.PSChildName)")
        Write-to-log("DNS Servers: $($dnsServers.NameServer)")
        $remediationNeeded = $true
    } else {
        Write-to-log("Interface: $($interface.PSChildName)")
        Write-to-log("DNS Servers: Automatically configured")
    }
    Write-to-log("-----------------------------------")
}

if ($remediationNeeded) {
    Write-to-log("Remediation Needed. Exiting with code 1.")
    Write-Host $log
    Exit 1
} else {
    Write-Host $log
    Exit 0
}