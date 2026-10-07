<#
.SYNOPSIS
    Converts App Volumes Packages to VHD format for use with In-Guest App Volumes
.DESCRIPTION
    This script connects to an App Volumes Manager server, retrieves the specified App Volumes Packages, downloads them from the associated datastore in vCenter, converts them to VHD format using qemu-img, and optionally copies them to a specified target path.    
.PARAMETER LogPath
    The path to the log file. Default is C:\Logs\AppVolMigrationToInGuest
.PARAMETER LogRollover
    The number of days before the log file is rolled over. Default is 5 days.
.PARAMETER AppVolumesServer
    The App Volumes Manager server to connect to. This is the source of the App Volumes Package details.
.PARAMETER AppVolumesUser
    The username to authenticate to the App Volumes Manager server. use name@domain.com format.
.PARAMETER AppVolumesPassword
    The password for the App VolumesUser.
.PARAMETER AppVolumesPackageNames
    An array of App Volumes Package names to convert. These should match the names in the App Volumes Manager.
.PARAMETER vCenter
    The vCenter server to connect to. This is used to download the App Volumes Package files from the datastore.
.PARAMETER vCenterUser
    The username to authenticate to the vCenter server. Use the admin@whatever.com format.
.PARAMETER vCenterPassword
    The password for the vCenterUser.
.PARAMETER vCenterDatacenter
    The name of the vCenter Datacenter where the App Volumes Package datastores are located.
.PARAMETER PackageLocalPath
    The local path to store the downloaded App Volumes Package files before conversion. For example, E:\Packages\Packages.
.PARAMETER PackageTargetPath
    An optional path to copy the converted VHD files to after conversion. This can be a network share. If not specified, the files will remain in the local PackageLocalPath.
.PARAMETER WritablesMode
    A switch to indicate that the script is being run in Writables mode.
.EXAMPLE
    $Params = @{
        AppVolumesServer        = "ws-av2.domain.com"
        AppVolumesUser          = "james@domain.com"
        AppVolumesPassword      = "LikeIwillg1veYouThis!"
        AppVolumesPackageNames  = @("Notepad++","Google Chrome")
        vCenter                 = "vcsa.mega.awesome.domain.com"
        vCenterUser             = "service@vsphere.local"
        vCenterPassword         = "G00dTryF00l!"
        vCenterDatacenter       = "DC1"
        PackageLocalPath        = "E:\Packages"
        PackageTargetPath       = "\\NutanixFiles\AppVolTestMig\appvolumes\packages"
    }
    & .\ConvertAppVolumesPackagesToVHD.ps1 @Params

    The example will take Notepad++ and Google Chrome App Volumes Packages from the App Volumes Manager server ws-av2.domain.com, download them from the associated datastore in vCenter, convert them to VHD format, and copy them to the specified network share.

.EXAMPLE
    $Params = @{
        AppVolumesServer        = "ws-av2.domain.com"
        AppVolumesUser          = "james@domain.com"
        AppVolumesPassword      = "LikeIwillg1veYouThis!"
        AppVolumesPackageNames  = @("DOMAIN\jk001 on W11x64")
        vCenter                 = "vcsa.mega.awesome.domain.com"
        vCenterUser             = "service@vsphere.local"
        vCenterPassword         = "G00dTryF00l!"
        vCenterDatacenter       = "DC1"
        PackageLocalPath        = "E:\Packages"
        PackageTargetPath       = "\\NutanixFiles\AppVolTestMig\appvolumes\writables"
        WritablesMode           = $true
    }
    & .\ConvertAppVolumesPackagesToVHD.ps1 @Params
    
    The example will take the "DOMAIN\jk001 on W11x64" writable from the App Volumes Manager server ws-av2.domain.com, download is from the associated datastore in vCenter, convert it to VHD format, and copy it to the specified network share.

#>

[CmdletBinding()]

param (
    [Parameter(Mandatory = $false)][string]$LogPath = "C:\Logs\AppVolMigrationToInGuestVHD.log", # Where we log to
    [Parameter(Mandatory = $false)][int]$LogRollover = 5, # Number of days before logfile rollover occurs
    [Parameter(Mandatory = $true)][string]$AppVolumesServer, # The App Volumes Manager server
    [Parameter(Mandatory = $true)][string]$AppVolumesUser, # UserName with access to App Volumes Manager
    [Parameter(Mandatory = $true)][string]$AppVolumesPassword, # Password for the App Volumes User
    [Parameter(Mandatory = $true)][Array]$AppVolumesPackageNames, # The name of the App Volumes Packages to convert
    [Parameter(Mandatory = $true)][string]$vCenter,
    [Parameter(Mandatory = $true)][string]$vCenterUser,
    [Parameter(Mandatory = $true)][string]$vCenterPassword,
    [Parameter(Mandatory = $true)][string]$vCenterDatacenter,
    [Parameter(Mandatory = $true)][string]$PackageLocalPath, # Local path to store the App Volumes Packages
    [Parameter(Mandatory = $false)][string]$PackageTargetPath, # Optional path to the final destination for the converted VHD files
    [Parameter(Mandatory = $false)][switch]$WritablesMode # Move the script to writables mode instead of app packages
)


#region Functions
# ============================================================================
# Functions
# ============================================================================
function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNullOrEmpty()][Alias("LogContent")][string]$Message,
        [Parameter(Mandatory = $false)][Alias('LogPath')][string]$Path = $LogPath,
        [Parameter(Mandatory = $false)][ValidateSet("Error", "Warn", "Info")][string]$Level = "Info",
        [Parameter(Mandatory = $false)][switch]$NoClobber
    )

    Begin {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
        }
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
        }
        else {
            # Nothing to see here yet.
        }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                #Write-Error $Message
                $LevelText = 'ERROR:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor Red
                
            }
            'Warn' {
                #Write-Warning $Message
                $LevelText = 'WARNING:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor Yellow
                
            }
            'Info' {
                #Write-Verbose $Message
                $LevelText = 'INFO:'
                Write-Host "$FormattedDate $LevelText $Message" -ForegroundColor White
            }
        }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End {
    }
}

function Start-Stopwatch {
    Write-Log -Message "Starting Timer" -Level Info
    $Global:StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
}

function Stop-Stopwatch {
    Write-Log -Message "Stopping Timer" -Level Info
    $StopWatch.Stop()

    if ($StopWatch.Elapsed.TotalSeconds -le 1) {
        Write-Log -Message "Script processing took $($StopWatch.Elapsed.TotalMilliseconds) ms to complete." -Level Info
    }
    elseif ($StopWatch.Elapsed.TotalMinutes -le 1) {
        Write-Log -Message "Script processing took $($StopWatch.Elapsed.TotalSeconds) seconds to complete." -Level Info
    }
    elseif ($StopWatch.Elapsed.TotalHours -le 1) {
        $minutes = [math]::Floor($StopWatch.Elapsed.TotalMinutes)
        $seconds = $StopWatch.Elapsed.Seconds
        Write-Log -Message "Script processing took $($minutes) minutes and $($seconds) seconds to complete." -Level Info
    }
    else {
        $hours = [math]::Floor($StopWatch.Elapsed.TotalHours)
        $minutes = $StopWatch.Elapsed.Minutes
        $seconds = $StopWatch.Elapsed.Seconds
        Write-Log -Message "Script processing took $($hours) hours, $($minutes) minutes, and $($seconds) seconds to complete." -Level Info
    }
}

function RollOverlog {
    $LogFile = $LogPath
    $LogOld = Test-Path $LogFile -OlderThan (Get-Date).AddDays(-$LogRollover)
    $RolloverDate = (Get-Date -Format "dd-MM-yyyy")
    if ($LogOld) {
        Write-Log -Message "$LogFile is older than $LogRollover days, rolling over" -Level Info
        $NewName = [io.path]::GetFileNameWithoutExtension($LogFile)
        $NewName = $NewName + "_$RolloverDate.log"
        Rename-Item -Path $LogFile -NewName $NewName
        Write-Log -Message "Old logfile name is now $NewName" -Level Info
    }    
}

function StartIteration {
    Write-Log -Message "--------Starting Iteration--------" -Level Info
    RollOverlog
    Start-Stopwatch
}

function StopIteration {
    Stop-Stopwatch
    Write-Log -Message "--------Finished Iteration--------" -Level Info
}
#endregion Functions

#region variables
# ============================================================================
# Variables
# ============================================================================
if ($WritablesMode -eq $true) {
    $migration_type = "writables"
} else {
    $migration_type = "packages"
}
#endregion variables

#region Execute
# ============================================================================
# Execute
# ============================================================================
StartIteration

#region check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 7) { 
    Write-Log -message "[ERROR] This script only supports PowerShell 7." -Level Error 
    Write-Log -Message "[INFO] PowerShell version is: $($PSVersionTable.PSVersion)" -Level Info
    StopIteration
    Exit 1
}
#endregion check PoSH version

#region validate Export Path
if (-not (Test-Path $PackageLocalPath)) {
    try {
        New-Item -Path $PackageLocalPath -ItemType Directory -Force -ErrorAction Stop
        Write-Log -Message "Created the specified local package path $($PackageLocalPath)." -Level Info
    } catch {
        Write-Log -Message "Failed to create the specified local package path $($PackageLocalPath). Please check the path and try again." -Level Error
        StopIteration
        Exit 1
    }
}
#endregion validate Export Path

#region handle qemu installation
#----------------------------------------------------------------------------
# Must install the qemu-img to get access to VHD conversion
$qemu_path = "C:\Program Files\qemu\qemu-img.exe"

if (Test-Path $qemu_path) {
    Write-Log -Message "qemu-img.exe found at $qemu_path" -Level Info
} else {
    Write-Log -Message "qemu-img.exe not found. Installing on this machine to get access to VHD conversion." -Level Warn
    If (-not (Test-Path ($qemu_path | Split-Path))) {
        try {
            $null = New-Item -Path ($qemu_path | Split-Path) -ItemType Directory -Force -ErrorAction Stop
            try {
                Install-Script -name install-qemu-img -Confirm:$false -Force -ErrorAction Stop
                $qemu_install_script_path = (Get-InstalledScript -Name install-qemu-img).InstalledLocation
                & "$qemu_install_script_path\install-qemu-img.ps1" -Force -ErrorAction Stop
                if (Get-Command qemu-img -ErrorAction SilentlyContinue) {
                    Write-Log -Message "qemu-img and command installed successfully" -Level Info
                } else {
                    Write-Log -Message "qemu-img command not found after installation. Please check the install-qemu-img script and try again." -Level Error
                    StopIteration
                    Exit 1
                }
            }
            catch {
                Write-Log -Message "Failed to install qemu-img using the install-qemu-img script. Please check the error and try again." -Level Error
                StopIteration
                Exit 1
            }
        } catch {
            Write-Log -Message "Failed to create the qemu directory $($qemu_path | Split-Path). Please check the path and try again." -Level Error
            StopIteration
            Exit 1
        }
    }
}
#endregion handle qemu installation

#region Handle PowerCLI Module and vCenter Connection
try {
    Write-Log -Message "Importing VMware PowerCLI Module" -Level Info
    $Modules = @("VMware.VimAutomation.Core","VMware.VimAutomation.Common")
    foreach ($moduleName in $Modules) {
        if (Get-Module -Name $moduleName -ListAvailable) {
            Write-Log -Message "$($moduleName) module found" -Level Info
            Import-Module $moduleName -ErrorAction Stop
        } else {
            Write-Log -Message "$($moduleName) module not found" -Level Warn
            try {
                Install-Module -Name VMware.PowerCLI -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                Write-Log -Message "VMware PowerCLI Module installed successfully" -Level Info
            } catch {
                Write-Log -Message "Failed to install VMware PowerCLI Module. Please install the VMware PowerCLI module from the PowerShell Gallery." -Level Error
                StopIteration
                Exit 1
            }
        }
    }
    Write-Log -Message "Connecting to vCenter Server $($vCenter)" -Level Info
    $null = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -ErrorAction Stop
    $null = Connect-VIServer -Server $vCenter -User $vCenterUser -Password $vCenterPassword -ErrorAction Stop
} catch {
    Write-Log -Message "Failed to import VMware PowerCLI Module. Please ensure it is installed." -Level Error
    StopIteration
    Exit 1
}
#endregion Handle PowerCLI Module and vCenter Connection

#region App Volumes API Authentication
#----------------------------------------------------------------------------
# This gets the session cookie for the App Volumes API
$AuthBody = @{
    username = $AppVolumesUser
    password = $AppVolumesPassword
}
$Body = $AuthBody | ConvertTo-Json
try {
    Write-Log -Message "Authenticating to App Volumes Server $($AppVolumesServer)" -Level Info
    $null = Invoke-RestMethod -Method POST -Uri "https://$($AppVolumesServer)/app_volumes/sessions" -Body $Body -ContentType "application/json" -ResponseHeadersVariable responseHeaders -SkipCertificateCheck
} catch {
    Write-Log -Message "Failed to authenticate to App Volumes Server $($AppVolumesServer). Please check the server name and credentials." -Level Error
    StopIteration
    Exit 1
}

$setCookieHeader = $responseHeaders.'Set-Cookie' -join ";"
$setCookieHeader -match "_session_id=([^;]+)" | out-null
$sessionId = $matches[1]

if ([string]::IsNullOrEmpty($sessionId)) {
    Write-Log -Message "Failed to retrieve session ID from App Volumes Server $AppVolumesServer. Please check the server name and credentials." -Level Error
    StopIteration
    Exit 1
} else {
    Write-Log -Message "Successfully authenticated to App Volumes Server $($AppVolumesServer) and retrieved session ID." -Level Info
}

# Now use the session ID in subsequent requests
$headers = @{
    Cookie = "_session_id=$sessionId"
}
#endregion App Volumes API Authentication

#region Get the App Volumes Package List
#----------------------------------------------------------------------------
try {
    Write-Log -Message "Retrieving App Volumes $($migration_type) list from $($AppVolumesServer)" -Level Info
    if ($WritablesMode -eq $true) {
        $app_volumes_package_list = Invoke-RestMethod -Method GET -Uri "https://$($AppVolumesServer)/app_volumes/writables" -Headers $headers -ContentType "application/json" -SkipCertificateCheck
    } else {
        $app_volumes_package_list = Invoke-RestMethod -Method GET -Uri "https://$($AppVolumesServer)/app_volumes/app_packages" -Headers $headers -ContentType "application/json" -SkipCertificateCheck
    }
} catch {
    Write-Log -Message "Failed to retrieve App Volumes $($migration_type) list from $($AppVolumesServer). Please check the server name and credentials." -Level Error
    StopIteration
    Exit 1
}

if ($app_volumes_package_list.data.Count -eq 0) {
    Write-Log -Message "No App Volumes $($migration_type) found on $AppVolumesServer. Please check the server and ensure there are packages available." -Level Warn
    StopIteration
    Exit 1
} else {
    Write-Log -Message "Retrieved $($app_volumes_package_list.data.Count) App Volumes $($migration_type) from $($AppVolumesServer)" -Level Info
    foreach ($package in $app_volumes_package_list.data) {
        Write-Log -Message "Found App Volumes $($migration_type): $($package.name)" -Level Info
    }
}
#endregion Get the App Volumes Package List

$packages_success = 0

#region Process Each App Volumes Package
#----------------------------------------------------------------------------
foreach ($package in $AppVolumesPackageNames) {
    # now we have a list of packages and the info we need to download the VMDK
    Write-Log -Message "Processing App Volumes $($migration_type) $($package)" -Level Info
    $app_package_name = $package
    $target_app_volumes_package = $app_volumes_package_list.data | Where-Object { $_.name -eq $app_package_name  }
    $target_package_filename = $target_app_volumes_package.filename
    $local_package_path = "$($PackageLocalPath)\$($app_package_name)\$target_package_filename"
    $target_package_datastore = $target_app_volumes_package.datastore_name
    $target_package_path = $target_app_volumes_package.path
    if ($WritablesMode -eq $true) {
        # Only required for writables
        $writable_attached_status = $target_app_volumes_package.attached
        if ($writable_attached_status -eq "Attached") {
            Write-Log -Message "The App Volumes writable $($app_package_name) is currently attached to a VM. Please detach it before proceeding." -Level Warn
            Continue
        }
    }
    
    Write-Log -Message "Processing target $($migration_type) Datastore: $($target_package_datastore) to download files" -Level Info
    $package_files_to_download = Get-ChildItem -Path "vmstore:\$($vCenterDatacenter)\$($target_package_datastore)\$($target_package_path)" | Where-Object { $_.name -like $($target_package_filename -replace ".vmdk",'*')}
    if ($WritablesMode -eq $true) {
        $package_files_to_download = $package_files_to_download | Where-Object { $_.name -notlike "*.json" } # Get rid of the .json files if we are dealing with writables
    } else {
        $package_files_to_download = $package_files_to_download | Where-Object { $_.name -notlike "*.metadata" } # Get rid of the .metadata files if we are not dealing with writables
    }
    
    Write-Log -Message "Found $($package_files_to_download.Count) files to download for $($migration_type) $($app_package_name)" -Level Info

    if ($package_files_to_download.Count -eq 0) {
        Write-Log -Message "No files found to download for $($migration_type) $($app_package_name). Please check the $($migration_type) name and try again." -Level Warn
        Continue
    } else {
        $package_file_download_success = 0
        foreach ($file in $package_files_to_download) {
            try {
                Write-Log -Message "Downloading $($file.name) to $($local_package_path | Split-Path)" -Level Info
                Copy-DatastoreItem -Item "vmstore:\$($vCenterDatacenter)\$($file.DatastoreFullPath -replace '\[','' -replace '\] ','\' -replace '/','\')" -Destination "$($local_package_path | Split-Path)\$($file.name)" -Force
                $package_file_download_success ++
            } catch {
                Write-Log -Message "Failed to download $($file.name) from $($target_package_datastore). Please check the path and try again." -Level Error
                Continue
            }
        }

        if ($package_file_download_success -ne $package_files_to_download.Count) {
            Write-Log -Message "Failed to download all files for $($migration_type) $($app_package_name). Only $($package_file_download_success) of $($package_files_to_download.Count) files downloaded successfully. Please check the errors and try again." -Level Error
            Continue
        } else {
            Write-Log -Message "Successfully downloaded all files for $($migration_type): $($app_package_name). Proceeding with conversion" -Level Info
        }
    }
    
    $converted_file_name_vhd = "$($local_package_path -replace '.vmdk','').vhd"
    if ($WritablesMode -ne $true) {
        $json_file_name = "$($local_package_path -replace '.vmdk','').json"
    }
    
    if ($WritablesMode -eq $true) {
        # we need the metadata file for writables
        try {
            $metadata_file_name = "$local_package_path.metadata" -replace '.vmdk','.vhd'
            Copy-Item -Path "$local_package_path.metadata" -Destination $metadata_file_name -Force -ErrorAction Stop
            # alter the metadata file contents to update the template description
            $metadata_file_contents = Get-Content -Path $metadata_file_name -ErrorAction Stop
            # Find the line that starts with :template_file_name:
            $metadata_file_contents = $metadata_file_contents | ForEach-Object {
                if ($_ -like ":template_file_name:*") {
                    $_.Replace('.vmdk"','.vmdk (converted to VHD)"')
                } else {
                    $_
                }
            }
            Set-Content -Path $metadata_file_name -Value $metadata_file_contents -ErrorAction Stop 
        }
        catch {
            Write-Log -Message "Failed to copy metadata file for $($app_package_name). Please check the file and try again." -Level Warn
            Continue
        }
    }
    
    try {
        Write-Log -Message "Converting $($target_package_filename) to VHD format using qemu-img" -Level Info 
        & $qemu_path convert -f vmdk -O vpc -o subformat=dynamic $local_package_path $converted_file_name_vhd -ErrorAction Stop
        $conversion_success = $true
    } catch {
        Write-Log -Message "Failed to convert $($local_package_path) to VHD. Please check the file and try again." -Level Error
        Continue
    }

    # Copy the data to destination shares
    if (-not [string]::IsNullOrEmpty($PackageTargetPath)) {
        if ($conversion_success -eq $true) {
            Write-Log -Message "Successfully converted package $($app_package_name). Proceeding with copy to $($PackageTargetPath)" -Level Info
            try {
                Copy-Item $converted_file_name_vhd -Destination $PackageTargetPath -ErrorAction Stop
            } catch {
                Write-Log -Message "Failed to copy $($converted_file_name_vhd) to $($PackageTargetPath). Please check the path and try again." -Level Error
            }

            if ($WritablesMode -eq $true) {
                # metadata file is needed for writables
                try {
                    Copy-Item $metadata_file_name -Destination $PackageTargetPath -ErrorAction Stop
                } catch {
                    Write-Log -Message "Failed to copy $($metadata_file_name) to $($PackageTargetPath). Please check the path and try again." -Level Error
                }
            } else {
                # json file is needed for app packages
                try {
                    Copy-Item $json_file_name -Destination $PackageTargetPath -ErrorAction Stop
                } catch {
                    Write-Log -Message "Failed to copy $($json_file_name) to $($PackageTargetPath). Please check the path and try again." -Level Error
                }
            }
        }
    }
    
    $packages_success ++
}

#endregion Execute

#region kill the App Volumes API Session
#----------------------------------------------------------------------------
try {
    Write-Log -Message "Terminating App Volumes API Session on $($AppVolumesServer)" -Level Info
    $null = Invoke-RestMethod -Method DELETE -Uri "https://$($AppVolumesServer)/app_volumes/sessions" -Headers $headers -ContentType "application/json" -SkipCertificateCheck -ErrorAction Stop
} catch {
    Write-Log -Message "Failed to terminate App Volumes API Session on $($AppVolumesServer). Please check the server and try again." -Level Warn
}

if ($packages_success -eq $AppVolumesPackageNames.Count) {
    Write-Log -Message "Successfully processed all $($packages_success) App Volumes $($migration_type)." -Level Info
} else {
    Write-Log -Message "Processed $($packages_success) of $($AppVolumesPackageNames.Count) App Volumes $($migration_type). Please check the errors and try again." -Level Warn
}
#endregion kill the App Volumes API Session

StopIteration
Exit 0
