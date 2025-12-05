################################################################################
# MIT License
#
# Copyright (c) 2024 Microsoft and Contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# 
# Filename: UninstallClassicTeams-Improved
# Version: 1
# Description: Script to cleanup old teams and corresponding regkeys for all users on machine.
#################################################################################


$applicationDefinitions = @(
    @{
        Name="Teams"
        DisplayName="Teams"
        Publisher="Microsoft"
        Exe="teams"
        IDs=@(
            ### Array of product ids to look for - unimplemented
            "731F6BAA-A986-45A4-8936-7C3AAAAA760B",
            "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"
        )
        RegistryKeys=@(
            ### Array of registry keys to match
            ### If a registry entry starts with the hive name the match is performed using StartsWith() - case insensitive 'hkey_\FooBar...' == 'hkey_\foobar...'
            ### If a registry entry lacks the hive name then the match is performed using EndsWith() - case insensitive '...FooBar' == '...foobar'
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
        )
        CleanUp=@(
            ### Array of cleanup steps
            @{
                RunUninstall=$true
                RemoveRegistryKeys=$true
                RemoveDirectory=$true
            }
        )
    }
)

$ScriptResult = @{
    NumProfiles = 0
	NumApplicationsFound = 0
	NumApplicationsRemoved = 0
    FindApplicationProfilesLoadedSuccessfully = 0
	FindApplicationProfilesLoadedFailed = 0
    FindApplicationProfilesUnloadedSuccessfully = 0
	FindApplicationProfilesUnloadedFailed = 0
    FindApplicationInstallationFound = 0
	RemoveApplicationProfilesLoadedSuccessfully = 0
	RemoveApplicationProfilesLoadedFailed = 0
	RemoveApplicationNumProfilesUnloadedSuccessfully = 0
	RemoveApplicationProfilesUnloadedFailed = 0
	RemoveApplicationUninstallionPerformed = 0
	StaleFileSystemEntryDeleted = 0
	AppDataEntryDeleted = 0
	StaleRegkeyEntryDeleted = 0
    TeamsMeetingAddinFolderDeleted = 0
	TeamsMeetingAddinDeleted = 0
	TeamsWideInstallerRunKeyDeleted = 0
	StaleUserAssociationRegkeyEntryDeleted = 0
}

# Function that creates the unique file path
function Get-UniqueFilename {
    param (
        [string]$BaseName,
        [string]$Extension = "txt",
        [string]$DateTimeFormat = "yyyyMMddHHmmss"
    )
    
    # Get the current date and time in the specified format
    $timestamp = (Get-Date).ToString($DateTimeFormat)
    
    # Combine the base name, timestamp, and extension
    $uniqueFilename = "$BaseName-$timestamp.$Extension"
    
    # Return the unique filename
    return $uniqueFilename
}

$Logfile = Get-UniqueFilename("$($ENV:SystemDrive)\Windows\Temp\Classic_Teams_Uninstallation")
 
function write-teams-log
{
   Param ([string]$LogString)
   $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
   $LogMessage = "$Stamp $LogString"
   Add-content $LogFile -value $LogMessage
   Write-host $LogMessage
}


# Function to find SID for user
function Get-SIDFromAlias {
    param (
        [string]$userAlias
    )
    
    try {
        # Create a NTAccount object from the user alias
        $ntAccount = New-Object System.Security.Principal.NTAccount($userAlias)
        
        # Translate NTAccount to SecurityIdentifier
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        
        # Output the SID
        return $sid.Value
    }
    catch {
        Write-Error "Failed to convert alias to SID: $_"
    }
}

# Function to find application installed as per specifications for all user profiles
function Find-WindowsApplication
{
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ApplicationDefinitions = $null,
        [switch]$AllUsers
    )

        
    if (
        (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) -or
        (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")))
    )
    {
        write-teams-log "Warning: $($MyInvocation.MyCommand): Running without elevated permissions will reduce functionality"
    }


    write-teams-log "$($MyInvocation.MyCommand): Searching for software..."
    $installedSoftware = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue
    $installedApps = Get-AppXPackage -ErrorAction SilentlyContinue
    $installed32bitComponents = @(Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | % { Get-ItemProperty $_.PsPath } | Select *)
    $installed64bitComponents = @(Get-ChildItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | % { Get-ItemProperty $_.PsPath } | Select *)
    $systemEnvironment = $(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -ErrorAction SilentlyContinue)
    $userComponents = @{}
    
    $foundApplicationList = @()
    $foundApplicationEntry = @{
        AppDefinition=$null
        Location=@{
            Software=@()
            Apps=@()
            Components=@{}
        }
        Found=$false
    }

    
    $componentSourceList = @{}

    $componentSourceList["SYSTEM"] = [psobject]@{
        Installed32BitComponents=$installed32bitComponents
        Installed64BitComponents=$installed64bitComponents
        Environment=$systemEnvironment
        RegFile=$null
        Username=$null
    }

    $componentSourceList["CURRENTUSER"] = [psobject]@{
        Installed32BitComponents=@(Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | % { Get-ItemProperty $_.PsPath } | Select *)
        Installed64BitComponents=@(Get-ChildItem "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | % { Get-ItemProperty $_.PsPath } | Select *)
        Environment=$(Get-ItemProperty "HKCU:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -ErrorAction SilentlyContinue)
        RegFile=$null
        Username="$($env:USERNAME)"
    }

    if ($AllUsers)
    {
        write-teams-log "$($MyInvocation.MyCommand): Getting list of installed software for each user..."
        
        foreach ($userDirectory in @(Get-ChildItem "$($ENV:SystemDrive)\users" -ErrorAction SilentlyContinue))
        {
            if ($userDirectory -ne $null)
            {
                $userName = "$($userDirectory.Name.ToLower())"
				$ScriptResult.NumProfiles++
                
                # write-teams-log "$($MyInvocation.MyCommand): Looking at user $($username) profile..."
				# write-teams-log "$($MyInvocation.MyCommand): Looking at user profile..."

                $userComponents["$($userName)"] = [psobject]@{
                    Installed32BitComponents=$null
                    Installed64BitComponents=$null
                    Environment=$null
                    RegFile=$null
                    Username=$null
                }
                $componentSourceList["$($userName)"] = $userComponents["$($userName)"]

                $process = $null
                try
                {
                    $command = "`"REG LOAD `"`"HKLM\$($userName)`"`" `"`"$($userDirectory.FullName)\NTUSER.DAT`"`""
                    $process = Start-Process "$($env:ComSpec)" -ArgumentList @("/c","$($command)") -Wait -WindowStyle Hidden  -PassThru
                    if ($process.ExitCode -eq 0)
                    {
						### good
						$ScriptResult.FindApplicationProfilesLoadedSuccessfully++
                    } else
                    {
						### ungood
						$ScriptResult.FindApplicationProfilesLoadedFailed++
						write-teams-log "Warning: $($MyInvocation.MyCommand): Profile loading failed with exit code $($process.ExitCode)"
                    }
                }
                catch
                {
					### ignore
					$ScriptResult.FindApplicationProfilesLoadedFailed++
					write-teams-log "Warning: $($MyInvocation.MyCommand): Profile loading caught exception. An error occurred: $_"
                }
                $userRegistry = Get-Item "HKLM:\$($userName)" -ErrorAction SilentlyContinue
                if ($userRegistry -ne $null)
                {
                    $userComponents["$($userName)"].RegFile="$($userDirectory.FullName)\NTUSER.DAT"
                    $userComponents["$($userName)"].Environment=$(Get-ItemProperty "HKLM:\$($userName)\Environment" -ErrorAction SilentlyContinue)
                    $userComponents["$($userName)"].Installed32BitComponents=@(Get-ChildItem "HKLM:\$($userName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | % { Get-ItemProperty $_.PsPath } | Select *)
                    $userComponents["$($userName)"].Installed64BitComponents=@(Get-ChildItem "HKLM:\$($userName)\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | % { Get-ItemProperty $_.PsPath } | Select *)
                    $componentSourceList["$($userName)"] = $userComponents["$($userName)"]
					
					$process = $null
					try
					{
						$command = "`"REG UNLOAD `"`"HKLM\$($userName)`"`""
						$process = Start-Process "$($env:ComSpec)" -ArgumentList @("/c","$($command)") -Wait -WindowStyle Hidden  -PassThru
						if ($process.ExitCode -eq 0)
						{
							### good
							$ScriptResult.FindApplicationProfilesUnloadedSuccessfully++
						} else
						{
							### ungood
							$ScriptResult.FindApplicationProfilesUnloadedFailed++
							write-teams-log "$($MyInvocation.MyCommand): Profile unloading failed with exit code $($process.ExitCode)"
						}
					}
					catch
					{
						### ignore
						$ScriptResult.FindApplicationProfilesUnloadedFailed++
						write-teams-log "$($MyInvocation.MyCommand): Profile loading caught exception. An error occurred: $_"
					}
                }
            }
        }
    }

    foreach ($appDef in $ApplicationDefinitions)
    {
        if ($appDef -ne $null)
        {
            $foundApplicationEntry = @{
                AppDefinition=$appDef
                Location=@{
                    Software=@()
                    Apps=@()
                    Components=@{}
                    Files=@()
                }
                Found=$false
            }

            if ($appDef.RegistryKeys -ne $null)
            {
                if ($appDef.RegistryKeys.Count -gt 0)
                {
                    
                    ### search components
                    foreach ($componentSource in $componentSourceList.Keys)
                    {
                        ### search each location
                        $currentRegFile = $($componentSourceList["$($componentSource)"].RegFile)
                        $currentSource = $componentSource
                        $currentRegKeys = @()

                        if ($componentSourceList["$($componentSource)"] -ne $null)
                        {
                            if ($componentSourceList["$($componentSource)"].Installed32BitComponents -ne $null)
                            {
                                if ($componentSourceList["$($componentSource)"].Installed32BitComponents.Count -gt 0)
                                {
                                    $currentRegKeys += @($componentSourceList["$($componentSource)"].Installed32BitComponents)
                                }
                            }
                            if ($componentSourceList["$($componentSource)"].Installed64BitComponents -ne $null)
                            {
                                if ($componentSourceList["$($componentSource)"].Installed64BitComponents.Count -gt 0)
                                {
                                    $currentRegKeys += @($componentSourceList["$($componentSource)"].Installed64BitComponents)
                                }
                            }
                        }
                        
                        for ($c = 0; $c -lt $currentRegKeys.Count; $c++)
                        {
                            $regList = @($currentRegKeys[$c])
                            for ($x = 0; $x -lt $regList.Count; $x++)
                            {
                                $appRegKey = $($regList[$x].PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))

                                for ($r = 0; $r -lt $appDef.RegistryKeys.Count; $r++)
                                {
                            
                                    $foundEntry = $false
                                    if ($appDef.RegistryKeys[$r].StartsWith("HKEY_"))
                                    {
                                        if ($appRegKey.ToLower().StartsWith($appDef.RegistryKeys[$r].ToLower()))
                                        {
                                            ### found
                                            $foundEntry = $true
                                        }
                                    } else
                                    {
                                        if ($appRegKey.ToLower().EndsWith($appDef.RegistryKeys[$r].ToLower()))
                                        {
                                            ### found
                                            $foundEntry = $true
                                        }
                                    }
                            
                                    if ($foundEntry -eq $true)
                                    {                                    
                                        write-teams-log "$($MyInvocation.MyCommand): Found application '$($appDef.Name)', adding in found application list"

										$componentKey = "$($regList[$x].DisplayName)" + ":" + "$($currentSource)"
                                        if ($foundApplicationEntry.Location.Components["$($componentKey)"] -eq $null)
                                        {
											$ScriptResult.FindApplicationInstallationFound++
                                            $foundApplicationEntry.Location.Components["$($componentKey)"] = @{
                                                Component=$($regList[$x])
                                                ComponentSource=$($currentSource)
                                                RegistryKeys=@()
                                                RegFile=$currentRegFile
                                            }
											
											$foundApplicationEntry.Location.Components["$($componentKey)"].RegistryKeys += $appRegKey
											$foundApplicationEntry.Found = $true
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ($foundApplicationEntry -ne $null)
            {
                if ($foundApplicationEntry.Found -eq $true)
                {
                    $foundApplicationList += $foundApplicationEntry
                }
            }
        }
    }

    return @($foundApplicationList)
}


# Function to remove application from the machine for all user profiles
# If application is already running, process shall be killed
# Uninstallation for user profiles is done based on Uninstall string
function Remove-WindowsApplication
{
    param(
        [Parameter(Mandatory)]
        [psobject[]]$Applications = $null
    )

        
    if (
        (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) -or
        (-not ([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")))
    )
    {
        write-teams-log "Warning: $($MyInvocation.MyCommand): Running without elevated permissions will reduce functionality"
    }


    write-teams-log "$($MyInvocation.MyCommand): Removing application(s)..."
	write-teams-log "-------------------"
    
    $removedApplicationList = $null
    $removedApplicationEntry = @{
        AppDefinition=$null
        Successful=$false
        Error=$null
    }

    if ($Applications)
    {
        $removedApplicationList = @()

		for ($a = 0; $a -lt $Applications.Count; $a++)
		{
                if ($Applications[$a] -ne $null)
                {
                    
                    if ([string]::IsNullOrEmpty($Applications[$a].AppDefinition.Exe) -eq $false)
                    {
                        ### look for running process
                        $processList = @(Get-Process -Name $($Applications[$a].AppDefinition.Exe) -ErrorAction SilentlyContinue)
                        if ($processList -ne $null)
                        {
                            if ($processList.Count -gt 0)
                            {
                                write-teams-log "$($MyInvocation.MyCommand): Stopping existing processes..." 
                                @($processList).Kill()
                            }
                        }
                    }

                    if ($Applications[$a].Found -eq $true)
                    {
                        $appEntry = $Applications[$a]
                        
                        if ($appEntry.AppDefinition -ne $null)
                        {
                            if ($appEntry.AppDefinition.CleanUp -ne $null)
                            {
                                write-teams-log "$($MyInvocation.MyCommand): Removing application '$($appEntry.AppDefinition.Name)'..."
                                if ($appEntry.Location -ne $null)
                                {
									if (
										($appEntry.Location.Apps) -or 
										($appEntry.Location.Components.Keys) -or 
										($appEntry.Location.Software) -or
										($appEntry.Location.Files)
									)
									{
										$removedApplicationEntry = $null

										if ($appEntry.Location.Components.Keys.Count -gt 0)
										{
											foreach ($componentName in $appEntry.Location.Components.Keys)
											{
												$componentObj = $($appEntry.Location.Components["$($componentName)"])
												if ($componentObj -ne $null)
												{
													if ($componentObj.Component -ne $null)
													{
														# write-teams-log "$($MyInvocation.MyCommand): Removing component for user..."

														if ([string]::IsNullOrEmpty($componentObj.Component.InstallLocation) -eq $false)
														{
															### have install path
															$installDir = Get-Item "$($componentObj.Component.InstallLocation)" -ErrorAction SilentlyContinue
															if ($installDir -ne $null)
															{
																### have actual path
																if ($appEntry.AppDefinition.CleanUp.RunUninstall -eq $true)
																{
																	$uninstallCommand = "$($componentObj.Component.UninstallString)"

																	if ([string]::IsNullOrEmpty($componentObj.Component.QuietUninstallString) -eq $false)
																	{
																		$uninstallCommand = "$($componentObj.Component.QuietUninstallString)"
																	}

																	# write-teams-log "Uninstall command : $uninstallCommand"
																	if ([string]::IsNullOrEmpty($uninstallCommand) -eq $false)
																	{
																		### Run uninstall
																		write-teams-log "$($MyInvocation.MyCommand): Running component uninstall..."

																		Start-Process "$($env:ComSpec)" -ArgumentList @("/c","$($uninstallCommand)") -Verb RunAs -Wait -WindowStyle Hidden
																		$ScriptResult.RemoveApplicationUninstallionPerformed++
																	} else
																	{
																		write-teams-log "Warning: $($MyInvocation.MyCommand): Component has no uninstall command."
																	}
																}

																### remove app path
																if ($appEntry.AppDefinition.CleanUp.RemoveDirectory -eq $true)
																{
																	write-teams-log "$($MyInvocation.MyCommand): Removing component directories..."
																	$ignore = Remove-Item "$($installDir.FullName)" -Recurse -Force -ErrorAction SilentlyContinue
																}

															} else
															{
																write-teams-log "Warning: $($MyInvocation.MyCommand): Component install path can't be found."
															}
														}


														### remove registry key(s)
														if ($appEntry.AppDefinition.CleanUp.RemoveRegistryKeys -eq $true)
														{                                                                    
															$regUser = $componentObj.ComponentSource

															if ($componentObj.RegistryKeys -ne $null)
															{
																if ($componentObj.RegistryKeys.Count -gt 0)
																{
																	write-teams-log "$($MyInvocation.MyCommand): Removing component registry key(s)..."

																	if ($componentObj.RegFile -ne $null)
																	{
																		### Load user's registry file
																		$regFile = $componentObj.RegFile

																		try
																		{
																			$output = Start-Process "$($env:ComSpec)" -ArgumentList @("/c","""REG LOAD """"HKLM\$($regUser)"""" """"$($regFile)"""" 1>NUL 2>NUL") -Wait -WindowStyle Hidden  -PassThru
																			$ScriptResult.RemoveApplicationProfilesLoadedSuccessfully++
																		}
																		catch
																		{
																			### ignore
																			$ScriptResult.RemoveApplicationProfilesLoadedFailed++
																			write-teams-log "Warning: $($MyInvocation.MyCommand): Profile loading caught exception. An error occurred: $_"
																		}
																	}

																	### Remove registry key(s)
																	for ($r = 0; $r -lt $componentObj.RegistryKeys.Count; $r++)
																	{
																		$regKey = "$($componentObj.RegistryKeys[$r].Replace('Microsoft.PowerShell.Core\Registry::',''))"
																		$ignore = Remove-Item "registry::$($regKey)" -Recurse -Force -ErrorAction SilentlyContinue
																	}

																	if ($componentObj.RegFile -ne $null)
																	{                                                                    
																		### Unload user's registry file
																		try
																		{
																			$output = Start-Process "$($env:ComSpec)" -ArgumentList @("/c","""REG UNLOAD """"HKLM\$($userName)"""" 1>NUL 2>NUL") -Wait -WindowStyle Hidden
																			$ScriptResult.RemoveApplicationNumProfilesUnloadedSuccessfully++
																		}
																		catch
																		{
																			### ignore
																			$ScriptResult.RemoveApplicationProfilesUnloadedFailed++
																			write-teams-log "Warning: $($MyInvocation.MyCommand): Profile unloading caught exception. An error occurred: $_"
																		}
																	}
																} else
																{
																	write-teams-log "Warning: $($MyInvocation.MyCommand): Component has no registry key(s)."
																}
															} else
															{
																write-teams-log "Warning: Warning: $($MyInvocation.MyCommand): Component has no registry key(s)."
															}
														}
													}
												}
											}
										}

										$removedApplicationEntry = @{
											AppDefinition=$appEntry.AppDefinition
											Successful=$true
											Error=$null
										}


										if ($removedApplicationEntry -ne $null)
										{
											$removedApplicationList += $removedApplicationEntry
										}
                                    }
                                }
                            }
                        }
                    }
                }
            }
    }

    if ($removedApplicationList -ne $null)
    {
        return @($removedApplicationList)
    }

    return $removedApplicationList
}

function Remove-DirectoryRecursively {
    param(
        [string]$dirPath
    )

    if (Test-Path $dirPath) {
        Remove-Item -Path $dirPath -Recurse -Force -ErrorAction SilentlyContinue
        return $true
    } else {
        return $false
    }
}

# Function to remove the stale user name entries whose entry is not present in HKLM/:{$username)
# Also cleans the Appdata folder
Function Remove-TeamsStaleUserProfileFileSystemEntries {
	$userProfiles = (Get-ChildItem "$($ENV:SystemDrive)\Users" -Directory -Exclude "Public", "Default", "Default User").FullName
	
	foreach($profile in $userProfiles) {
		# Removing the complete old teams directory
		$userProfileTeamsPath = Join-Path -Path $profile -ChildPath "\AppData\Local\Microsoft\Teams\"
		$result = Remove-DirectoryRecursively -dirPath $userProfileTeamsPath
		if ($result) {
			$ScriptResult.StaleFileSystemEntryDeleted++
			write-teams-log "Deleted stale file system entry successfully."
		}
		
		$userProfileTeamsAppDataPath = Join-Path -Path $profile -ChildPath "\AppData\Roaming\Microsoft\Teams"
		$result2 = Remove-DirectoryRecursively -dirPath $userProfileTeamsAppDataPath
		if ($result2) {
			$ScriptResult.AppDataEntryDeleted++
			write-teams-log "Deleted stale App data file system entry successfully."
		}
	}
}

# Function to remove TMA entries
#Function Remove-TeamsMeetingAddin {
#
#	$userProfiles = (Get-ChildItem "$($ENV:SystemDrive)\Users" -Directory -Exclude "Public", "Default", "Default User").FullName
#	
#	foreach($profile in $userProfiles) {
#		# Removing the complete old teams directory
#		$userProfileTMAPath = Join-Path -Path $profile -ChildPath "\AppData\Local\Microsoft\TeamsMeetingAddin"
#		$result = Remove-DirectoryRecursively -dirPath $userProfileTMAPath
#		if ($result) {
#			$ScriptResult.TeamsMeetingAddinFolderDeleted++
#			write-teams-log "Deleted TMA folder successfully."
#		}
#	}

    #$UninstallKeys = @(
    #"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    #"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
   # "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    #)

    #$programFound = $false
    #foreach ($Key in $UninstallKeys) {
   #  Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like "*Microsoft Teams Meeting Add-in for Microsoft Office*"} | ForEach-Object {$programFound = $true
  #      write-teams-log "Found program: $($_.DisplayName)"
 #        $msiProductCode = $_.PSChildName
#         if ($msiProductCode) {
        #    write-teams-log "Starting uninstallation for Product Code: $msiProductCode"
       #         Start-Process "msiexec.exe" -ArgumentList "/x $msiProductCode /qn ALLUSERS=1" -Wait
      #          write-teams-log "Uninstallation process completed."
     #           $ScriptResult.TeamsMeetingAddinDeleted++
    #        } else {
   #             write-teams-log "No Product Code found for this program, unable to uninstall using msiexec."
  #          }
 #       }
#    }

 #   if (-not $programFound) {
  #      write-teams-log "The program was not found in the registry."
  #  }


# Function to remove only stale regkey entries from the HKEY_USERS
Function Remove-TeamsStaleRegKeys {
	$subkeys = (Get-ChildItem -Path "registry::HKEY_USERS"  -Exclude .DEFAULT).Name
	
	foreach($subkey in $subkeys) {
		$regkey = "registry::$subkey\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
		if (Test-Path $regkey) {
			$ignore = Remove-Item "$regKey" -Recurse -Force -ErrorAction SilentlyContinue
			write-teams-log "Deleted stale regkey entry from HKEY_USERS successfully."
			$ScriptResult.StaleRegkeyEntryDeleted++
		}
		
		# Very Rare scenario, if classic teams is chosen delibrately by user as default for msteams.
		$associationKeyPath = "registry::$subkey\SOFTWARE\Microsoft\Office\Teams\Capabilities\URLAssociations"
		if (Test-Path $associationKeyPath) {
			$res = Get-ItemProperty -Path $regkey -Name 'msteams' -ErrorAction SilentlyContinue
			
			if ($res -ne $null) {
				$ignore = Remove-ItemProperty -Path $associationKeyPath -Name 'msteams' -ErrorAction SilentlyContinue
				write-teams-log "Deleted URL association msteams entry."
				$ScriptResult.StaleUserAssociationRegkeyEntryDeleted++
			}
		}
	}
}

# Function to remove machine wide installer 
Function Remove-TeamsMachineWideInstaller {

    $ProductCode = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"
    $installed = Get-WmiObject Win32_Product | Where-Object { $_.IdentifyingNumber -eq $ProductCode }
    if ($installed) {
        Write-Output "AMD64 Machine-wide installer found. Attempting to remove..."
        Start-Process "msiexec.exe" -ArgumentList "/x $ProductCode /qn ALLUSERS=1" -Wait
		write-teams-log "Uninstalled machine wide 64-bit installer with Product Code $ProductCode"
    } else {
        Write-Output "AMD64 Machine-wide installer with Product Code $ProductCode is NOT installed."
    }

    $ProductCode = "{39AF0813-FA7B-4860-ADBE-93B9B214B914}"
    $installed = Get-WmiObject Win32_Product | Where-Object { $_.IdentifyingNumber -eq $ProductCode }
    if ($installed) {
        Write-Output "x86 Machine-wide installer found. Attempting to remove..."
        Start-Process "msiexec.exe" -ArgumentList "/x $ProductCode /qn ALLUSERS=1" -Wait
		write-teams-log "Uninstalled machine wide 64-bit installer with Product Code $ProductCode"
    } else {
        Write-Output "x86 Machine-wide installer with Product Code $ProductCode is NOT installed."
    }
	
	# if msiexec.exe is not uninstalling Teams wide installer from machine
	# Here performing following additional actions to remove Teams wide installer
	# 1. Removing the regkey "TeamsMachineInstaller" from Run key
	
	$regPathWOW6432Node = "registry::HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
	$valueName = 'TeamsMachineInstaller'
	if (Test-Path $regPathWOW6432Node) {
		$regValue = Get-ItemProperty -Path $regPathWOW6432Node -Name $valueName -ErrorAction SilentlyContinue

		if ($regValue -ne $null) {
			Remove-ItemProperty -Path $regPathWOW6432Node -Name $valueName -Force
			$ScriptResult.TeamsWideInstallerRunKeyDeleted++
			write-teams-log "Teams wide installer uninstall step. The registry value '$valueName' has been deleted."
		} else {
			write-teams-log "Teams wide installer uninstall step. The registry value '$valueName' does not exist."
		}
	}
	
	$regPath = "registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
	if (Test-Path $regPath) {
		$regValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue

		if ($regValue -ne $null) {
			Remove-ItemProperty -Path $regPath -Name $valueName -Force
			$ScriptResult.TeamsWideInstallerRunKeyDeleted++
			write-teams-log "Teams wide installer uninstall step. The registry value '$valueName' has been deleted."
		} else {
			write-teams-log "Teams wide installer uninstall step. The registry value '$valueName' does not exist."
		}
	}
	
	# Uninstall Teams Machine-Wide Installer
	$msiExecPath = "${Env:ProgramFiles(x86)}\Teams Installer\"

	# Delete the Teams Installer folder if it exists
	if (Test-Path $msiExecPath) {
		Remove-Item -Path $msiExecPath -Recurse -Force
	}
}

Function New-PostScriptExecutionRegkeyEntry {
	$registryPath = "registry::HKLM\Software\Microsoft\TeamsAdminLevelScript"
	$null = New-Item -Path $registryPath -Force -ErrorAction SilentlyContinue
}

write-teams-log "Looking for application(s): $($applicationDefinitions.Name -join ', ')"
$foundList = Find-WindowsApplication -ApplicationDefinitions $applicationDefinitions -AllUsers
if ($foundList)
{
	$ScriptResult.NumApplicationsFound = $foundList.Count
	write-teams-log "Found $(@($foundList).Count.ToString('#,###')) application(s)"
	#"Removing apps..."
	$removeList = Remove-WindowsApplication -Applications @($foundList)
	if ($removeList -ne $null)
	{
		$ScriptResult.NumApplicationsRemoved = $removeList.Count
		write-teams-log "Removed applications: $(@($removeList | Where-Object { $_.Successful -eq $true }).AppDefinition.Name -join ', ')"
	} else
	{
		write-teams-log "Warning: No application(s) were removed."
	}
} else
{
    write-teams-log "Warning: Didn't find any applications."
}

Try {
# Function to remove only stale regkey entries from the HKEY_USERS
Remove-TeamsStaleRegKeys

# Function to remove the stale user name entries whose entry is not present in HKLM/:{$username)
Remove-TeamsStaleUserProfileFileSystemEntries

# Function to remove TMA entries
#Remove-TeamsMeetingAddin

# Function to remove machine wide installer 
Remove-TeamsMachineWideInstaller

New-PostScriptExecutionRegkeyEntry

# Deleting the shortcuts
$TeamsIcon_old = "$($ENV:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams*.lnk"
Get-Item $TeamsIcon_old | Remove-Item -Force -Recurse

$ScriptResult | ConvertTo-Json -Compress

if (Test-Path $Logfile) {
    # Read the log file line by line
    Get-Content -Path $Logfile | ForEach-Object {
        Write-Host $_
    }
} else {
    Write-Host "The log file does not exist at the specified path: $Logfile"
}

Write-Host "All removal steps complete. Exiting with code 0"
Exit 0
}
Catch {
    Write-Host "An error occoured. Exiting with code 1"
    Exit 1
}