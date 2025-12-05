# Get all network interfaces from the registry
$interfaces = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

foreach ($interface in $interfaces) {

    # Get the DNS server addresses
    $dnsServers = Get-ItemProperty -Path $interface.PSPath -Name "NameServer" -ErrorAction SilentlyContinue

    if ($dnsServers.NameServer -like "*1.1.*" -or $dnsServers.NameServer -like "*8.8.*" -or $dnsServers.NameServer -like "*192.168.*" -or $dnsServers.NameServer -like "*208.67.*" -or $dnsServers.NameServer -like "*9.9.*" -or $dnsServers.NameServer -like "*149.112.*") {
        Write-Output "Public DNS name servers detected - Removing DNS server entries."
        Write-Output "Interface: $($interface.PSChildName)"
        Write-Output "DNS Servers: $($dnsServers.NameServer)"
        try {
            Set-ItemProperty -Path $interface.PSPath -Name "NameServer" -Value ""
            Write-Host "Sucsessfully removed Public DNS name server entries for interface $($interface.PSChildName)."
        } catch {
            Write-Output "ERROR Could not reset the NameServer registry value for interface $($interface.PSChildName)."
            Exit 1
        }
    } else {
        Write-Output "Interface: $($interface.PSChildName)"
        Write-Output "DNS Servers: Automatically configured."
    }
    Write-Output "-----------------------------------"
}

Exit 0
