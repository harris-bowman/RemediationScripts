[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[bool]$detected = $false

function Write-to-log {
   Param ([string]$LogString)
   $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
   $LogMessage = "$Stamp $LogString"
   Write-host $LogMessage
}

try {
    $installedPackages = Get-Package * -ProviderName msi
}
catch {
    write-to-log "No packages found for Get-Package * -ProviderName msi"
}

$targetPackages = @(
    "Microsoft Teams classic"
    "Teams Machine-Wide Installer"
)

foreach ($packageName in $targetPackages) {
    $packageFound = $installedPackages | Where-Object {$_.Name -ieq $packageName -or $_.Name.Trim() -ieq $packageName}
    if ($packageFound) {
        write-to-log "The package '$packageName' is installed. "
        $detected = $true
    } else {
        write-to-log "The package '$packageName' is NOT installed. "
    }
}

$installedWMIWin32ClassProducts = Get-WmiObject -Class Win32_Product
$installedWMIWin32AddRemovePrograms = Get-WmiObject -Class Win32Reg_AddRemovePrograms

$targetObjects = @(
    "*Microsoft Teams classic*"
    "*Teams Machine-Wide Installer*"
)

foreach ($objectName in $targetObjects) {
    $objectFound = $installedWMIWin32ClassProducts | Where-Object {$_.Name -like $objectName}
    if ($objectFound) {
        write-to-log "Win32_Product '$objectName' is present. "
        $detected = $true
    } else {
        write-to-log "Win32_Product '$objectName' is NOT present. "
    }
}
foreach ($objectName in $targetObjects) {
    $objectFound = $installedWMIWin32AddRemovePrograms | Where-Object {$_.DisplayName -like $objectName}
    if ($objectFound) {
        write-to-log "Win32AddRemovePrograms object '$objectName' is present. "
        $detected = $true
    } else {
        write-to-log "Win32AddRemovePrograms object '$objectName' is NOT present. "
    }
}

$UninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

#foreach ($Key in $UninstallKeys) {
#    try{
#        Get-ItemProperty -Path $Key | Where-Object {$_.DisplayName -like "*Microsoft Teams Meeting Add-in for Microsoft Office*"} 
#        | ForEach-Object {
#        $msiProductCode = $_.PSChildName
#        Write-to-log "Found program: $($_.DisplayName)"
#        if ($msiProductCode) {
#            Write-to-log "Found uninstallation for Microsoft Teams Meeting Add-in for Microsoft Office Product Code: $msiProductCode"
#            $detected = $true
#            } else {
#                Write-to-log "No Product Code found for this program, will need manual uninstallation."
#            }
#    } -ErrorAction SilentlyContinue
#    }
#    catch {
#        Write-to-log "Microsoft Teams Meeting Add-in for Microsoft Office not found in $Key"
#    }
    
#}
foreach ($programName in $targetObjects) {
    foreach ($Key in $UninstallKeys) {
        try {
            Get-ItemProperty -Path $Key | Where-Object {$_.DisplayName -like $programName} | ForEach-Object {
            $msiProductCode = $_.PSChildName
            Write-to-log "Found program: $($_.DisplayName)"
            if ($msiProductCode) {
                Write-to-log "Found uninstallation for $programName Product Code: $msiProductCode"
                $detected = $true
                } else {
                    Write-to-log "No Product Code found for $programName, will need manual uninstallation."
                }
        } -ErrorAction SilentlyContinue
        }
        catch {
            Write-to-log "Microsoft Teams classic not found in $Key"
        }
    }

}

if ($detected){
    Exit 1
} else {
    Exit 0
}