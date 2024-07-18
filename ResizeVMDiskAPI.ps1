
<#
.SYNOPSIS
    This script will resize a disk on a VM (or VMs) in a Nutanix Prism Element cluster using the Nutanix Prism Element API.
.DESCRIPTION
    Inspired as a follow up from Andrew Gresbach's question on World of EUC, this script will resize a disk on a VM (or VMs) in a Nutanix Prism Element cluster using the Nutanix Prism Element API. 
    It's a loose follow on from Kees Baggerman's https://blog.myvirtualvision.com/2019/11/19/nutanix-ahv-and-citrix-mcs-adding-a-persistent-disk-via-powershell-v2/
.PARAMETER LogPath
    The path to the log file. Default is C:\Logs\ResizePersistentDisk.log
.PARAMETER LogRollover
    The number of days before the logfile rolls over. Default is 5 days.
.PARAMETER ClusterIP
    The IP address of the Nutanix Prism Element cluster.
.PARAMETER PE_Username
    The username for the Prism Element user.
.PARAMETER PE_Password
    The password for the Prism Element user.
.PARAMETER DeviceBus
    The device bus of the disk to resize. Default is "scsi".
.PARAMETER DeviceIndex
    The device index of the disk to resize. This is a mandatory parameter. Can be 0, 1, 2 etc.
.PARAMETER VMNames
    An array of VM names whose disk you want to resize.
.PARAMETER GBToAdd
    The number of GB to add to the disk.
.PARAMETER Whatif
    A switch to enable planning mode. Default is False
.PARAMETER DisableParamPrompt
    A switch to disable the prompt for user input when outputting param details. Default is False
.EXAMPLE
    .\ResizeVMDiskAPI.ps1 -ClusterIP "1.1.1.1" -PE_Username "secret_user_name" -PE_Password "super_mega_password" -DeviceBus "scsi" -DeviceIndex 1 -VMNames @("VM1", "VM2") -GBToAdd 10 -Whatif
    This will execute the script in whatif mode, to resize the disk on VM1 and VM2 by 10GB for the SCSI disk at index 1.
.EXAMPLE
    .\ResizeVMDiskAPI.ps1 -ClusterIP "1.1.1.1" -PE_Username "secret_user_name" -PE_Password "super_mega_password" -DeviceBus "scsi" -DeviceIndex 1 -VMNames @("VM1", "VM2") -GBToAdd 10
    This will execute the script to resize the disk on VM1 and VM2 by 10GB for the SCSI disk at index 1.
.EXAMPLE
    .\ResizeVMDiskAPI.ps1 -ClusterIP "1.1.1.1" -PE_Username "secret_user_name" -PE_Password "super_mega_password" -DeviceBus "scsi" -DeviceIndex 1 -VMNames @("VM1", "VM2") -GBToAdd 10 -disableparamprompt
    This will execute the script to resize the disk on VM1 and VM2 by 10GB for the SCSI disk at index 1. This will disable the prompt for user input when outputting param details.
.NOTES 
    Script comes without warranty. Use at your own risk and test first. The Whatif switch is there for a reason
#>

#region Params
# ============================================================================
# Parameters
# ============================================================================

[CmdletBinding()]

Param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\ResizePersistentDisk.log", 

    [Parameter(Mandatory = $false)]
    [int]$LogRollover = 5, # number of days before logfile rollover occurs

    [Parameter(Mandatory=$true)]
    [string]$ClusterIP,

    [Parameter(Mandatory=$true)]
    [string]$PE_Username,

    [Parameter(Mandatory=$true)]
    [string]$PE_Password,

    [Parameter(Mandatory=$false)]
    [string]$DeviceBus = "scsi",

    [Parameter(Mandatory=$true)]
    [string]$DeviceIndex, # 0, 1, 2 etc

    [Parameter(Mandatory=$true)]
    [Array]$VMNames,

    [Parameter(Mandatory=$true)]
    [int]$GBToAdd,

    [Parameter(Mandatory=$false)]
    [switch]$Whatif,

    [Parameter(Mandatory=$false)]
    [switch]$DisableParamPrompt
)
#endregion Params

#region Functions
# ============================================================================
# Functions
# ============================================================================

function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [Alias('LogPath')]
        [string]$Path = $LogPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warn", "Info", "Plan")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory = $false)]
        [switch]$NoClobber
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
                Write-Host $Message -ForegroundColor Red
                $LevelText = 'ERROR:'
            }
            'Warn' {
                Write-Host $Message -ForegroundColor Yellow
                $LevelText = 'WARNING:'
            }
            'Info' {
                Write-Host $Message -ForegroundColor Green
                $LevelText = 'INFO:'
            }
            'Plan' {
                Write-Host $Message -ForegroundColor Cyan
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
    else {
        Write-Log -Message "Script processing took $($StopWatch.Elapsed.TotalSeconds) seconds to complete." -Level Info
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

#region output params
# ============================================================================
# Output Params
# ============================================================================
Write-Log -Message "---------------------------------------------" -Level Plan
Write-Log -Message "PARAM OUTPUT: ClusterIP: $($ClusterIP)" -Level Plan
Write-Log -Message "PARAM OUTPUT: PE_Username: $($PE_Username)" -Level Plan
Write-Log -Message "PARAM OUTPUT: PE_Password: ##Hidden##" -Level Plan
foreach ($VMName in $VMNames) {
    Write-Log -Message "PARAM OUTPUT: VMName to process: $($VMName)" -Level Plan
}
Write-Log -Message "PARAM OUTPUT: GBToAdd: $($GBToAdd)" -Level Plan
Write-Log -Message "PARAM OUTPUT: DeviceBus: $($DeviceBus)" -Level Plan
Write-Log -Message "PARAM OUTPUT: DeviceIndex: $($DeviceIndex)" -Level Plan
Write-Log -Message "PARAM OUTPUT: Whatif: $($Whatif)" -Level Plan
Write-Log -Message "---------------------------------------------" -Level Plan

if ($DisableParamOutput -eq $true) {
    #---------------------------------------------
    # Prompt the user to enter 'Y' to continue or any other key to exit
    #---------------------------------------------
    $Input = Read-Host -Prompt "Enter Y to continue or any other key to exit"
    if ($Input -ne "Y") {
        Write-Log -Message "You chose to exit. Exiting script." -Level Plan
        #Exit 0
    }
}

#endregion output params

#region Execute
# ============================================================================
# Execute
# ============================================================================
StartIteration

# Check if PowerShell version is 7 or higher
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Log -Message "This script requires PowerShell 7 or higher." -Level Warn
    Break
}

#---------------------------------------------
# Handle basic Auth
#---------------------------------------------
# create the HTTP Basic Authorization header
$pair = $PE_Username + ":" + $PE_Password
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"

# setup the request headers
$Headers = @{
    'Accept'        = 'application/json'
    'Authorization' = $basicAuthValue
    'Content-Type'  = 'application/json'
}

#---------------------------------------------
# Get a list of VMs in Prism Element
# https://www.nutanix.dev/api_reference/apis/prism_v2.html#tag/vms/operation/get/vms/getVMs
#---------------------------------------------
$Method = "GET"
$RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/vms/?include_vm_disk_config=true"

try {
    Write-Log -Message "Getting a list of VMs in Prism Element: $($ClusterIP)" -Level Info
    $VirtualMachines = Invoke-RestMethod -Uri $RequestUri -Headers $Headers -Method $Method -TimeoutSec 5 -UseBasicParsing -DisableKeepAlive -SkipCertificateCheck -ErrorAction Stop
    Write-Log -Message "Retrieved $($VirtualMachines.entities.Count) VMs from Prism Element: $($ClusterIP)" -Level Info
}
catch {
    Write-Log -Message "Failed to get a list of VMs in Prism Element: $($ClusterIP)" -Level Error
    Write-Log -Message $_ -Level Error
    StopIteration
    Exit 1 
}

#---------------------------------------------
# Create Counter Objects
#---------------------------------------------

$VMToProcessCount = ($VMNames | Measure-Object).Count
$VMToProcessCurrentIteration= 1
$VMsSuccessCount = 0
$VMsFailedCount = 0

#---------------------------------------------
# Process each VM
#---------------------------------------------
foreach ($VMName in $VMNames) {
    if ($Whatif) {
        # Whatif Planning Mode
        Write-Log -Message "Planning: Processing VM $($VMToProcessCurrentIteration) of $($VMToProcessCount): $($VMName)" -Level Plan
    } else {
        Write-Log -Message "Processing VM $($VMToProcessCurrentIteration) of $($VMToProcessCount): $($VMName)" -Level Info
    }

    #---------------------------------------------
    # Filter to the VM whose disk we want to resize
    #---------------------------------------------
    $Target_VM = $VirtualMachines.entities | Where-Object { $_.name -eq $VMName }
    if ($null -eq $Target_VM) {
        Write-Log -Message "Failed to find VM: $($VMName)" -Level Warn
        $VMsFailedCount ++
        Continue
    } 
    else {
        $Target_VM_Disk = $Target_VM.vm_disk_info.disk_address | Where-Object { $_.device_bus -eq $DeviceBus -and $_.device_index -eq $DeviceIndex}
        if ($null -eq $Target_VM_Disk) {
            Write-Log -Message "Failed to find disk on VM: $($VMName) with DeviceBus: $($DeviceBus) and DeviceIndex: $($DeviceIndex)" -Level Warn
            $VMsFailedCount ++
            Continue
        }
    }
    
    #---------------------------------------------
    # Get the detail about the virtual disk
    # https://www.nutanix.dev/api_reference/apis/prism_v2.html#tag/virtual_disks/operation/get/virtual_disks/%7Buuid%7D/getVirtualDisk
    #---------------------------------------------
    $Method = "GET"
    $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/virtual_disks/$($Target_VM_Disk.vmdisk_uuid)"

    try {
        Write-Log -Message "Getting the detail about the virtual disk: $($Target_VM_Disk.vmdisk_uuid)" -Level Info
        $Virtual_Disk = Invoke-RestMethod -Uri $RequestUri -Headers $Headers -Method $Method -TimeoutSec 5 -UseBasicParsing -DisableKeepAlive -SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Failed to get the detail about the virtual disk: $($Target_VM_Disk.vmdisk_uuid)" -Level Error
        Write-Log -Message $_ -Level Error
        $VMsFailedCount ++
        Continue
    }

    #---------------------------------------------
    # Figure out the new size in bytes
    #---------------------------------------------
    $Current_disk_size_in_bytes = $Virtual_Disk.disk_capacity_in_bytes
    $New_disk_size_in_bytes = $Current_disk_size_in_bytes + ($GBToAdd * 1024 * 1024 * 1024)

    if ($Whatif) {
        # Whatif Planning Mode
        Write-Log -Message "Planning: Would Update the disk size for VM: $($VMName) from $($Current_disk_size_in_bytes) ($($($Current_disk_size_in_bytes) / 1024 / 1024 / 1024) GiB) to $($New_disk_size_in_bytes) ($($($New_disk_size_in_bytes) / 1024 / 1024 / 1024) GiB)" -Level Plan
        $VMsSuccessCount ++
    } else {
        #---------------------------------------------
        # Update the disk size
        # https://www.nutanix.dev/api_reference/apis/prism_v2.html#tag/vms/operation/put/vms/%7Buuid%7D/disks/update/updateDisk
        #---------------------------------------------
        $Method = "PUT"
        $RequestUri = "https://$($ClusterIP):9440/PrismGateway/services/rest/v2.0/vms/$($Target_VM.uuid)/disks/update"
        $PayloadContent = @{
            vm_disks = @(
                @{
                    disk_address = @{
                        vmdisk_uuid = $Target_VM_Disk.vmdisk_uuid
                        device_uuid = $Target_VM_Disk.device_uuid
                        device_index = $Target_VM_Disk.device_index
                        device_bus = $Target_VM_Disk.device_bus
                    }
                    flash_mode_enabled = $false
                    is_cdrom = $false
                    is_empty = $false
                    vm_disk_create = @{
                        storage_container_uuid = $Virtual_Disk.storage_container_uuid
                        size = $New_disk_size_in_bytes
                    }
                }
            )
        }
        $Payload = (ConvertTo-Json $PayloadContent -Depth 4)

        try {
            Write-Log -Message "Updating the disk size for VM: $($VMName) from $($Current_disk_size_in_bytes) ($($($Current_disk_size_in_bytes) / 1024 / 1024 / 1024) GiB) to $($New_disk_size_in_bytes) ($($($New_disk_size_in_bytes) / 1024 / 1024 / 1024) GiB)" -Level Info
            $Update_VM_Disk = Invoke-RestMethod -Uri $RequestUri -Headers $Headers -Method $Method -Body $Payload -TimeoutSec 5 -UseBasicParsing -DisableKeepAlive -SkipCertificateCheck -ErrorAction Stop
            $VMsSuccessCount ++
        }
        catch {
            Write-Log -Message "Failed to update the disk size for VM: $($VMName)" -Level Error
            Write-Log -Message $_ -Level Error
            $VMsFailedCount ++
            Continue
        }
    }
    
    $VMToProcessStartCount ++
}

if ($Whatif) {
    # Whatif Planning Mode
    Write-Log -Message "Planning: Assumed success for $($VMsSuccessCount) VMs" -Level Plan
    if ($VMsFailedCount -gt 0) {
        Write-Log -Message "Planning: Failed to process $($VMsFailedCount) VMs" -Level Warn
    }
    
} else {
    Write-Log -Message "Successfully processed $($VMsSuccessCount) VMs" -Level Info
    if ($VMsFailedCount -gt 0) {
        Write-Log -Message "Failed to process $($VMsFailedCount) VMs. Please check logfile $($LogPath)" -Level Warn
    }
}

StopIteration
Exit 0
#endregion Execute






