<#
.SYNOPSIS
    An art of the possible (only do this if you really need to) script which will alter a VM boot configuration from BIOS to UEFI or Secure Boot, or vice versa. This script is dangerous and can render your VM unbootable if not configured correctly.
.DESCRIPTION
    The script will take a list of VMs and alter their boot configuration from BIOS to UEFI or Secure Boot, or vice versa. The script will also allow you to add or remove a vTPM from the VM.
.PARAMETER LogPath
    Optional. Logpath output for all operations. Default path is C:\Logs\PrismCentralBootSwitch.log
.PARAMETER LogRollover
    Optional. Number of days before logfiles are rolled over. Default is 5.
.PARAMETER pc_source
    Mandatory. The Prism Central Source to target.
.PARAMETER VMNames
    Mandatory. An Array of VMs to target as known by Prism Central.
.PARAMETER AddVTPM
    Optional. Switch. Add a vTPM to the VM. Cannot be used with the EnableBIOS parameter. Cannot be used with the RemoveVTPM parameter.
.PARAMETER RemoveVTPM
    Optional. Switch. Remove a vTPM from the VM. Cannot be used with the AddVTPM parameter.
.PARAMETER EnableSecureBoot
    Optional. Switch. Enable Secure Boot on the VM. Cannot be used with the EnableBIOS parameter. Cannot be used with the EnableUEFI parameter.
.PARAMETER EnableBIOS
    Optional. Switch. Revert to BIOS on the VM. Cannot be used with the EnableSecureBoot parameter. Cannot be used with the EnableUEFI parameter.
.PARAMETER EnableUEFI
    Optional. Switch. Enable UEFI on the VM. Cannot be used with the EnableSecureBoot parameter. Cannot be used with the EnableBIOS parameter.
.PARAMETER UseCustomCredentialFile
    Optional. Switch. Will call the Get-CustomCredentials function which keeps outputs and inputs a secure credential file base on Stephane Bourdeaud from Nutanix functions.
.PARAMETER CredPath
    Optional. Used if using the UseCustomCredentialFile parameter. Defines the location of the credential file. The default is "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials".
.PARAMETER Whatif
    Optional. Will process the script in planning mode with no changes.
.EXAMPLE
    & UpdateVMBoot.ps1 -pc_source "1.1.1.1" -VMNames "VM1","VM2,"VM3" -EnableSecureBoot -AddVTPM -Whatif
    Will process VM1, VM2, and VM3 on the Prism Central instance 1.1.1.1. It will enable Secure Boot and add a vTPM to the VMs. It will not make any changes and will only report on what it would do. You will be prompted for Credentials
.EXAMPLE
    & UpdateVMBoot.ps1 -pc_source "1.1.1.1" -VMNames "VM1","VM2,"VM3" -AddVTPM -Whatif
    will process VM1, VM2, and VM3 on the Prism Central instance 1.1.1.1 and add a vTPM to the VMs. It will not make any changes and will only report on what it would do. You will be prompted for Credentials
.EXAMPLE
    & UpdateVMBoot.ps1 -pc_source "1.1.1.1" -VMNames "VM1","VM2,"VM3" -BIOS -RemoveVTPM -Whatif
    Will process VM1, VM2, and VM3 on the Prism Central instance 1.1.1.1. It will revert the VMs to BIOS and remove the vTPM from the VMs. It will not make any changes and will only report on what it would do. You will be prompted for Credentials
.EXAMPLE
    & UpdateVMBoot.ps1 -pc_source "1.1.1.1" -VMNames "VM1","VM2,"VM3" -EnableSecureBoot -AddVTPM -UseCustomCredentialFile
    Will process VM1, VM2, and VM3 on the Prism Central instance 1.1.1.1. It will enable Secure Boot and add a vTPM to the VMs. You will be prompted for Credentials which will be stored for future use. You aren in execute mode.

.NOTES
    https://www.nutanix.dev/api_reference/apis/prism_v3.html#tag/vms/paths/~1vms~1%7Buuid%7D/put

    #------------------------------------------
    #             DISCLAIMER                  #
    #------------------------------------------

    You, the executor of this script, are responsible for ensuring that your guest OS is configured appropriately to allow the changes that this script will make.

    To be very clear, this script does not consider, care, or check for any in guest configurations. If your Windows VM, or any other VM that you target for that matter, is not configured appropriately, altering it's boot type will render it unbootable.

    To be even more clear, go read this document from Microsoft first: https://learn.microsoft.com/en-us/windows/deployment/mbr-to-gpt

    There is a reason Nutanix doesn't expose the ability to switch things over in the UI. It's because it's dangerous and can render your VM unbootable.

    USE THE WHATIF PARAMETER. IT IS THERE FOR A REASON.

.NOTES 
    Additonal detail on what this script logic aims to follow:
    - Process Each Machine but first, understand that machines current configuration and what can and what can't be done. For example:
        - You cannot add a vTPM to a machine that already has one, nor can you add one to a machine that uses BIOS boot. 
        - With the same logic, you cannot switch a machine from UEFI boot to BIOS boot without removing the vTPM first.
        - You also cannot have an IDE CDROM drive attached a VM that is going to be converted to SecureBoot, so we remove that, and then force machine_type to q35.
    - Each time a VM is altered, or going to be altered, a backup of that VM is exported to JSON for reference under the logs folder.

#>

#region Params
# ============================================================================
# Parameters
# ============================================================================
Param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\PrismCentralBootSwitch.log", # Where we log to

    [Parameter(Mandatory = $false)]
    [int]$LogRollover = 5, # Number of days before logfile rollover occurs

    [Parameter(Mandatory = $true)]
    [string]$pc_source,

    [Parameter(Mandatory = $true)]
    [Array]$VMNames,

    [Parameter(Mandatory = $false)]
    [switch]$AddVTPM = $false, # Add a vTPM to the VM

    [Parameter(Mandatory = $false)]
    [switch]$RemoveVTPM = $false, # Remove a vTPM from the VM

    [Parameter(Mandatory = $false)]
    [switch]$EnableSecureBoot = $false, # Enable Secure Boot on the VM

    [Parameter(Mandatory = $false)]
    [switch]$EnableBIOS = $false, # Revert to BIOS on the VM

    [Parameter(Mandatory = $false)]
    [switch]$EnableUEFI = $false, # Enable UEFI on the VM

    [Parameter(Mandatory = $false)]
    [switch]$UseCustomCredentialFile, # specifies that a credential file should be used

    [Parameter(Mandatory = $false)]
    [String]$CredPath = "$Env:USERPROFILE\Documents\WindowsPowerShell\CustomCredentials", # Default path for custom credential file

    [Parameter(Mandatory = $false)]
    [switch]$Whatif

)
#endregion

#$pc_source = "10.68.68.94"
#$VMNames = @("cont-jk-jump")

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
        [ValidateSet("Error", "Warn", "Info", "OK", "Plan")]
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
                Write-host $Message -ForegroundColor Red
                #Write-Error $Message
                $LevelText = 'ERROR:'
            }
            'Warn' {
                Write-Host $Message -ForegroundColor Yellow
                #Write-Warning $Message
                $LevelText = 'WARNING:'
            }
            'Info' {
                Write-Host $Message -ForegroundColor Green
                #Write-Verbose $Message
                $LevelText = 'INFO:'
            }
            'OK' {
                Write-Host $Message -ForegroundColor Green
                $LevelText = 'INFO:'
            }
            'Plan' {
                Write-Host $Message -ForegroundColor Cyan
                $LevelText = 'INFO:'
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

function Set-CustomCredentials {
    #input: path, credname
    #output: saved credentials file
    <#
    .SYNOPSIS
    Creates a saved credential file using DAPI for the current user on the local machine.
    .DESCRIPTION
    This function is used to create a saved credential file using DAPI for the current user on the local machine.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER path
    Specifies the custom path where to save the credential file. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
    .PARAMETER credname
    Specifies the credential file name.
    .EXAMPLE
    .\Set-CustomCredentials -path c:\creds -credname prism-apiuser
    Will prompt for user credentials and create a file called prism-apiuser.txt in c:\creds
    #>
    param
    (
        [parameter(mandatory = $false)]
        [string]$path,
        
        [parameter(mandatory = $true)]
        [string]$credname
    )

    begin {
        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            }
            else {
                $path = $CredPath
            }
            Write-Log -Message "[Credentials] Set path to $path" -Level Info
        } 
    }
    process {
        #prompt for credentials
        $credentialsFilePath = "$path\$credname.txt"
        $credentials = Get-Credential -Message "Enter the credentials to save in $path\$credname.txt"
        
        #put details in hashed format
        $user = $credentials.UserName
        $securePassword = $credentials.Password
        
        #convert secureString to text
        try {
            $password = $securePassword | ConvertFrom-SecureString -ErrorAction Stop
        }
        catch {
            Write-Log -Message "[Credentials] Could not convert password : $($_.Exception.Message)" -Level Warn
            StopIteration
            Exit 1
        }

        #create directory to store creds if it does not already exist
        if (!(Test-Path $path)) {
            try {
                $result = New-Item -type Directory $path -ErrorAction Stop
            } 
            catch {
                Write-Log -Message "[Credentials] Could not create directory $path : $($_.Exception.Message)" -Level Warn
                StopIteration
                Exit 1
            }
        }

        #save creds to file
        try {
            Set-Content $credentialsFilePath $user -ErrorAction Stop
        } 
        catch {
            Write-Log -Message "[Credentials] Could not write username to $credentialsFilePath : $($_.Exception.Message)" -Level Warn
            StopIteration
            Exit 1
        }
        try {
            Add-Content $credentialsFilePath $password -ErrorAction Stop
        } 
        catch {
            Write-Log -Message "[Credentials] Could not write password to $credentialsFilePath : $($_.Exception.Message)" -Level Warn
            StopIteration
            Exit 1
        }

        Write-Log -Message "[Credentials] Saved credentials to $credentialsFilePath" -Level Info              
    }
    end
    {}
} #this function is used to create saved credentials for the current user

function Get-CustomCredentials {
    #input: path, credname
    #output: credential object
    <#
    .SYNOPSIS
    Retrieves saved credential file using DAPI for the current user on the local machine.
    .DESCRIPTION
    This function is used to retrieve a saved credential file using DAPI for the current user on the local machine.
    .NOTES
    Author: Stephane Bourdeaud
    .PARAMETER path
    Specifies the custom path where the credential file is. By default, this will be %USERPROFILE%\Documents\WindowsPowershell\CustomCredentials.
    .PARAMETER credname
    Specifies the credential file name.
    .EXAMPLE
    .\Get-CustomCredentials -path c:\creds -credname prism-apiuser
    Will retrieve credentials from the file called prism-apiuser.txt in c:\creds
    #>
    param
    (
        [parameter(mandatory = $false)]
        [string]$path,
        
        [parameter(mandatory = $true)]
        [string]$credname
    )

    begin {
        if (!$path) {
            if ($IsLinux -or $IsMacOS) {
                $path = $home
            }
            else {
                $path = $Credpath
            }
            Write-Log -Message "[Credentials] Retrieving credentials from $path" -Level Info
        } 
    }
    process {
        $credentialsFilePath = "$path\$credname.txt"
        if (!(Test-Path $credentialsFilePath)) {
            Write-Log -Message "[Credentials] Could not access file $credentialsFilePath : $($_.Exception.Message)" -Level Warn
        }

        $credFile = Get-Content $credentialsFilePath
        $user = $credFile[0]
        $securePassword = $credFile[1] | ConvertTo-SecureString

        $customCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $securePassword

        Write-Log -Message "[Credentials] Returning credentials from $credentialsFilePath" -Level Info
    }
    end {
        return $customCredentials
    }
} #this function is used to retrieve saved credentials for the current user

function InvokePrismAPI {
    param (
        [parameter(mandatory = $true)]
        [ValidateSet("POST", "GET", "DELETE", "PUT")]
        [string]$Method,

        [parameter(mandatory = $true)]
        [string]$Url,

        [parameter(mandatory = $false)]
        [string]$Payload,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    BEGIN {}
    PROCESS {
        try {
            #check powershell version as PoSH 6 Invoke-RestMethod can natively skip SSL certificates checks and enforce Tls12 as well as use basic authentication with a pscredential object
            if ($PSVersionTable.PSVersion.Major -gt 5) {
                $headers = @{
                    "Content-Type" = "application/json";
                    "Accept"       = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $Method -Uri $url -Headers $headers -Body $payload -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                }
                else {
                    $resp = Invoke-RestMethod -Method $Method -Uri $url -Headers $headers -SkipCertificateCheck -SslProtocol Tls12 -Authentication Basic -Credential $credential -ErrorAction Stop
                }
            }
            else {
                $username = $credential.UserName
                $password = $credential.Password
                $headers = @{
                    "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username + ":" + ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))) ));
                    "Content-Type"  = "application/json";
                    "Accept"        = "application/json"
                }
                if ($payload) {
                    $resp = Invoke-RestMethod -Method $Method -Uri $url -Headers $headers -Body $payload -ErrorAction Stop
                }
                else {
                    $resp = Invoke-RestMethod -Method $Method -Uri $url -Headers $headers -ErrorAction Stop
                }
            }
        }
        catch {
            $saved_error = $_.Exception.Message
            Write-Log -Message "[ERROR] $saved_error" -Level Error
            
        }
        finally {
            #add any last words here; this gets processed no matter what
        }
    }
    END {
        return $resp
    }
}

function GetPCVMIncrements {
    param (
        [parameter(mandatory = $true)]
        [int]$offset
    )
    #----------------------------------------------------------------------------------------------------------------------------
    # Set API call detail
    #----------------------------------------------------------------------------------------------------------------------------
    $Method = "POST"
    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/list"
    $PayloadContent = @{
        kind   = "vm"
        length = 500
        offset = $offset
    }
    $Payload = (ConvertTo-Json $PayloadContent)
    #----------------------------------------------------------------------------------------------------------------------------
    Write-Log -Message "[VM Retrieval] Retrieving machines from offset $($offset) under PC: $($pc_source)" -Level Info
    try {
        $vm_list = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
        $vm_list = $vm_list.entities
        Write-Log -Message "[VM Retrieval] Retrieved $($vm_list.Count) virtual machines from offset $($Offset) under PC: $($pc_source)" -Level Info
        #Now we need to add them to the existing $VirtualMachinesArray
        $Global:VirtualMachines = ($Global:VirtualMachines + $vm_list)
        Write-Log -Message "[VM Retrieval] Retrieved VM Count is $($Global:VirtualMachines.Count) under PC: $($pc_source)" -Level Info
    }
    catch {
        Write-Log -Message "[VM Retrieval] Failed to retrieve virtual machines from $($pc_source)" -Level Warn
        StopIteration
        Exit 1
    }
}

function Get-PrismCentralTask {
    param (
        [parameter(mandatory = $true)]
        [ValidateSet("POST", "GET", "DELETE", "PUT")]
        [string]$Method,

        [parameter(mandatory = $true)]
        [string]$Url,

        [parameter(mandatory = $false)]
        [string]$Payload,

        [parameter(mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    BEGIN {
        Write-Log -Message "[PC Task] Polling PC for task status" -Level Info
    }
    PROCESS {
        try {
            $task_details = InvokePrismAPI -Method $Method -Url $Url -Credential $Credential -ErrorAction Stop

            if ($task_details.percentage_complete -ne "100") {
                Do { 
                    Start-Sleep 5
                    $task_details = InvokePrismAPI -Method $Method -Url $Url -Credential $Credential -ErrorAction Stop
                    if ($task_details.status -ne "running") {
                        if ($task_details.status -ne "succeeded") {
                            Write-Log -Message "[PC Task] Task: $($task_details.operation_type) failed with the status $($task_details.status) and error $($task_details.error_detail)" -Level Warn
                        }
                    }
                } 
                While ($task_details.percentage_complete -ne "100")
            }
            else {
                if ($task_details.status -ine "succeeded") {
                    Write-Log -Message "[PC Task] Task $($task_details.operation_type) status is $($task_details.status): $($task_details.progress_message)" -Level Warn
                }
                else {
                    Write-Log -Message "[PC Task] Task $($task_details.operation_type) completed successfully" -Level Info
                }
            } 
        }
        catch {
            Write-Log -Message "$_" -Level Warn
        }
    }
    END {
        return $task_details.status
    }
}

#endregion

#Region Execute
# ============================================================================
# Execute
# ============================================================================
StartIteration

#region Param Validation

if ($AddVTPM -and $RemoveVTPM) {
    Write-Log -Message "[PARAM ERROR]: You cannot specify both AddVTPM and Remove VTPM at the same time" -Level Warn
    StopIteration
    Exit 0
}
if ($EnableSecureBoot -and $EnableBIOS) {
    Write-Log -Message "[PARAM ERROR]: You cannot specify both EnableSecureBoot and EnableBIOS at the same time" -Level Warn
    StopIteration
    Exit 0
}
if ($EnableSecureBoot -and $EnableUEFI) {
    Write-Log -Message "[PARAM ERROR]: You cannot specify both EnableSecureBoot and EnableUEFI at the same time" -Level Warn
    StopIteration
    Exit 0
}
if ($EnableBIOS -and $EnableUEFI) {
    Wriite-Log -Message "[PARAM ERROR]: You cannot specify both EnableBIOS and EnableUEFI at the same time" -Level Warn
    StopIteration
    Exit 0
}
if ($EnableBIOS -and $AddVTPM) {
    Write-Log -Message "[PARAM ERROR]: You cannot specify both EnableBIOS and AddVTPM at the same time" -Level Warn
    StopIteration
    Exit 0
}
#endregion Param Validation

#region script parameter reporting
# ============================================================================
# Script processing detailed reporting
# ============================================================================
Write-Log -Message "---------------------------------------------" -Level Plan
Write-Log -Message "[Script Params] LogPath = $($LogPath)" -Level Plan
Write-Log -Message "[Script Params] LogRollover = $($LogRollover)" -Level Plan
Write-Log -Message "[Script Params] Nutanix pc_source = $($pc_source)" -Level Plan
foreach ($VMName in $VMNames) {
    Write-Log -Message "[Script Params] VMName = $($VMName)" -Level Plan
}
Write-Log -Message "[Script Params] AddVTPM = $($AddVTPM)" -Level Plan
Write-Log -Message "[Script Params] RemoveVTPM = $($RemoveVTPM)" -Level Plan
Write-Log -Message "[Script Params] EnableSecureBoot = $($EnableSecureBoot)" -Level Plan
Write-Log -Message "[Script Params] EnableBIOS = $($EnableBIOS)" -Level Plan
Write-Log -Message "[Script Params] EnableUEFI = $($EnableUEFI)" -Level Plan
Write-Log -Message "[Script Params] UseCustomCredentialFile = $($UseCustomCredentialFile)" -Level Plan
Write-Log -Message "[Script Params] CredPath = $($CredPath)" -Level Plan
Write-Log -Message "[Script Params] Whatif = $($Whatif)" -Level Plan
Write-Log -Message "---------------------------------------------" -Level Plan
#endregion script parameter reporting

#check PoSH version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Log -Message "[PoSH Version] Detected PoSH version $($PSVersionTable.PSVersion.Major). This script requires PoSH 7 or higher" -Level Warn
    StopIteration
    Exit 0
}

#region Authentication
#------------------------------------------------------------
# Handle Authentication
#------------------------------------------------------------
if ($UseCustomCredentialFile.IsPresent) {
    # credentials for PC
    $PrismCentralCreds = "prism-central-creds"
    Write-Log -Message "[Credentials] UseCustomCredentialFile has been selected. Attempting to retrieve credential object" -Level Info
    try {
        $PrismCentralCredentials = Get-CustomCredentials -credname $PrismCentralCreds -ErrorAction Stop
    }
    catch {
        Set-CustomCredentials -credname $PrismCentralCreds
        $PrismCentralCredentials = Get-CustomCredentials -credname $PrismCentralCreds -ErrorAction Stop
    }
}
else {
    # credentials for PC
    Write-Log -Message "[Credentials] Prompting user for Prism Central credentials" -Level Info
    $PrismCentralCredentials = Get-Credential -Message "Enter Credentials for Prism Central Instances"
    if (!$PrismCentralCredentials) {
        Write-Log -Message "[Credentials] Failed to set user credentials" -Level Warn
        StopIteration
        Exit 1
    }
}
#endregion Authentication

#region Get Cluster list
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "POST"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/clusters/list"
$PayloadContent = @{
    kind = "cluster"
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------
try {
    Write-Log -Message "[Cluster Retrieval] Attempting to retrieve Clusters from $($pc_source)" -Level Info
    $Clusters = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
    if ($Clusters) {
        Write-Log -Message "[Cluster Retrieval] Successfully retrieved Clusters from $($pc_source)" -Level Info
    }
}
catch {
    Write-Log -Message "[Cluster Retrieval] Failed to retrieve Clusters from $($pc_source)" -Level Warn
    StopIteration
    Exit 1
}

$NtxClusters = $Clusters.entities | Where-Object { $_.status.name -ne "Unnamed" -and $_.status.name -notin $ExcludeClusters }

if ($null -ne $NtxClusters) {
    Write-Log -Message "[Cluster Retrieval] Identified $($NtxClusters.Count) Clusters under PC: $($pc_source)" -Level Info
}
else {
    Write-Log -Message "[Cluster Retrieval] Failed to retrieve Cluster info from $($pc_source)" -Level Error
    StopIteration
    Exit 1
}
#endregion Get Cluster list

#region Get VM list
#---------------------------------------------
## Get the list of VMs
#---------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------
# Set API call detail
#----------------------------------------------------------------------------------------------------------------------------
$Method = "POST"
$RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/list"
$PayloadContent = @{
    kind   = "vm"
    length = 500
}
$Payload = (ConvertTo-Json $PayloadContent)
#----------------------------------------------------------------------------------------------------------------------------

try {
    Write-Log -Message "[VM Retrieval] Attempting to retrieve virtual machines from $($pc_source)" -Level Info
    $VirtualMachines = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials -ErrorAction Stop
    # We need to understand if we are above 500 machines, and if we need to loop through incremental pulls
    $vm_total_entity_count = $VirtualMachines.metadata.total_matches
    Write-Log -Message "[VM Retrieval] Successfully retrieved virtual machines from $($pc_source)" -Level Info
}
catch {
    Write-Log -Message "[VM Retrieval] Failed to retrieve virtual machines from $($pc_source)" -Level Warn
    StopIteration
    Exit 1
}

$VirtualMachines = $VirtualMachines.entities

if ($null -ne $VirtualMachines) {
    Write-Log -Message "[VM Retrieval] Retrieved $($VirtualMachines.Count) virtual machines under PC: $($pc_source)" -Level Info
}
else {
    Write-Log -Message "[VM Retrieval] Failed to retrieve virtual machine info from $($pc_source)" -Level Error
    StopIteration
    Exit 1
}

#region bulk machine retrieval from PC

#Configuration Limit reached - bail
if ($vm_total_entity_count -gt 25000) {
    Write-Log -Message "[VM Retrieval] 25K VM limit reached. This is not a supported configuration. Exiting script." -Level Warn
    StopIteration
    Exit 1
}

$api_batch_increment = 500

if ($vm_total_entity_count -gt 500) {
    # Set the variable to Global for this run
    $Global:VirtualMachines = $VirtualMachines
    Write-Log -Message "[VM Retrieval] $($vm_total_entity_count) virtual machines exist under PC: $($pc_source). Looping through batch pulls" -Level Info
    # iterate through increments of 500 until the offset reaches or exceeds the value of $vm_total_entity_count.
    for ($offset = 500; $offset -lt $vm_total_entity_count; $offset += $api_batch_increment) {
        $vm_offset = $offset
        GetPCVMIncrements -offset $vm_offset
    }
}

# Set the variable back to normal
if ($vm_total_entity_count -gt 500) {
    $VirtualMachines = $Global:VirtualMachines
}
#endregion bulk machine retrieval from PC

$LEGACY_Boot_Machines = $VirtualMachines | Where-Object { $_.spec.resources.boot_config.boot_type -eq "LEGACY" }
$UEFI_Boot_Machines = $VirtualMachines | Where-Object { $_.spec.resources.boot_config.boot_type -eq "UEFI" }
$SECURE_BOOT_Boot_Machines = $VirtualMachines | Where-Object { $_.spec.resources.boot_config.boot_type -eq "SECURE_BOOT" }
$VTPM_Machines = $VirtualMachines | Where-Object { $_.spec.resources.vtpm_config.vtpm_enabled -eq $true }

Write-Log -Message "[VM Retrieval] Found $($LEGACY_Boot_Machines.Count) VMs with LEGACY boot type" -Level Info
Write-Log -Message "[VM Retrieval] Found $($UEFI_Boot_Machines.Count) VMs with UEFI boot type" -Level Info
Write-Log -Message "[VM Retrieval] Found $($SECURE_BOOT_Boot_Machines.Count) VMs with SECURE_BOOT boot type" -Level Info
Write-Log -Message "[VM Retrieval] Found $($VTPM_Machines.Count) VMs with vTPM enabled" -Level Info
#endregion Get VM list

#region Counter Objects
#---------------------------------------------
# Create Counter Objects
#---------------------------------------------

$VMToProcessCount = ($VMNames | Measure-Object).Count
$VMToProcessCurrentIteration = 1
$VMSAlteredCountBoot = 0
$VMSAlteredCountvTPM = 0
$VMSAlteredCountCDROM = 0
$VMsFailedCount = 0
$VMSNotAltered = 0
#endregion Counter Objects

#region Process VMs
foreach ($VMName in $VMNames) {
    #------------------------------------------------------------
    # Check the VM exists in the existing Array
    #------------------------------------------------------------
    $VM = $VirtualMachines | Where-Object { $_.status.name -eq $VMName }
    if ($VM) {
        Write-Log -Message "Processing VM $($VMToProcessCurrentIteration) of $($VMToProcessCount): $($VMName)" -Level Info
        $VMToProcessCurrentIteration ++
        Write-Log -Message "[VM: $($VMName)] Found VM $($VM.status.name) in PC" -Level Info
        #------------------------------------------------------------
        # Check the current machine BIOS settings
        #------------------------------------------------------------
        $VM_Boot_Type = $VM.spec.resources.boot_config.boot_type
        if ([string]::IsNullOrEmpty($VM_Boot_Type)) {
            Write-Log -Message "[VM: $($VMName)] Unable to determine boot type from JSON. Not processing any further." -Level Warn
            $VMSNotAltered ++
            Continue 
        }
        if ($VM_Boot_Type -eq "LEGACY") {
            Write-Log -Message "[VM: $($VMName)] Boot type is set to BIOS (LEGACY)" -Level Info
        } 
        if ($VM_Boot_Type -eq "UEFI") {
            Write-Log -Message "[VM: $($VMName)] Boot type is set to UEFI" -Level Info
        } 
        if ($VM_Boot_Type -eq "SECURE_BOOT") {
            Write-Log -Message "[VM: $($VMName)] Boot type is set to SECURE_BOOT" -Level Info
        }
        #------------------------------------------------------------
        # Check the current machine vTPM settings
        #------------------------------------------------------------
        # Need to check this considering we have the ability to go back to BIOS boot
        $VM_vTPM = $VM.spec.resources.vtpm_config.vtpm_enabled
        if ($VM_vTPM -eq $true) {
            Write-Log -Message "[VM: $($VMName)] Has a vTPM enabled" -Level Info
        } else {
            Write-Log -Message "[VM: $($VMName)] Does not have a vTPM enabled" -Level Info
        }

        #------------------------------------------------------------
        # Check to see if the VM has an IDE CDROM
        #------------------------------------------------------------
        if ($VM.spec.resources.disk_list.device_properties.device_type -eq "CDROM" -and $VM.spec.resources.disk_list.device_properties.disk_address.adapter_type -eq "IDE") {
            if ($EnableSecureBoot) {
                Write-Log -Message "[VM: $($VMName)] Has an IDE CDROM attached which will be removed" -Level Warn
            } else {
                Write-Log -Message "[VM: $($VMName)] Has an IDE CDROM attached" -Level Info
            }
            $VM_Has_IDE_CDROM = $true
        }

        #------------------------------------------------------------
        # Process the VM
        #------------------------------------------------------------

        if ($Whatif) {
            # We are in a planning mode
            #------------------------------------------------------------
            # Handle BIOS
            #------------------------------------------------------------
            if ($VM_Boot_Type -eq "LEGACY" -and $EnableUEFI) {
                Write-Log -Message "[VM: $($VMName)] [Planning] Would change Boot type to UEFI" -Level Plan
                $VMSAlteredCountBoot ++
            }
            if ($VM_Boot_Type -eq "LEGACY" -and $EnableSecureBoot) {
                if ($VM_Has_IDE_CDROM = $true) {
                    Write-Log -Message "[VM: $($VMName)] [Planning] Would remove IDE CDROM and set machine tye to q35" -Level Plan
                    $VMSAlteredCountCDROM ++
                }
                Write-Log -Message "[VM: $($VMName)] [Planning] Would change Boot type to SECURE_BOOT" -Level Plan
                $VMSAlteredCountBoot ++
            }
            if ($VM_Boot_Type -eq "LEGACY" -and $EnableBIOS) {
                Write-Log -Message "[VM: $($VMName)] [Planning] Is already configured as boot type LEGACY. Nothing to change" -Level Plan
                $VMSNotAltered ++
            }
            #------------------------------------------------------------
            # Handle UEFI
            #------------------------------------------------------------
            if ($VM_Boot_Type -eq "UEFI" -and $EnableUEFI) {
                Write-Log -Message "[VM: $($VMName)] [Planning] Boot type is already UEFI. Nothing to change" -Level Plan
                $VMSNotAltered ++
            }
            if ($VM_Boot_Type -eq "UEFI" -and $EnableSecureBoot) {
                Write-Log -Message "[VM: $($VMName)] [Planning] Would change Boot type to SECURE_BOOT" -Level Plan
                $VMSAlteredCountBoot ++
            }
            if ($VM_Boot_Type -eq "UEFI" -and $EnableBIOS) {
                Write-Log -Message "[VM: $($VMName)] [Planning] Would change Boot type to LEGACY" -Level Plan
                $VMSAlteredCountBoot ++
                if ($VM_vTPM -eq $true) {
                    Write-Log -Message "[VM: $($VMName)] [Planning] Would remove vTPM" -Level Plan
                    $VMSAlteredCountvTPM ++
                }
            } 
            
            #------------------------------------------------------------
            # Handle Secure Boot
            #------------------------------------------------------------
            if ($VM_Boot_Type -eq "SECURE_BOOT" -and $EnableSecureBoot) {
                Write-Log -Message "[VM: $($VMName)] [Planning] Boot type is already SECURE_BOOT. Nothing to change" -Level Plan
                $VMSNotAltered ++
            }
            if ($VM_Boot_Type -eq "SECURE_BOOT" -and $EnableUEFI) {
                Write-Log -Message "[VM: $($VMName)] [Planning] Would change Boot type to UEFI" -Level Plan
                $VMSAlteredCountBoot ++
            }
            if ($VM_Boot_Type -eq "SECURE_BOOT" -and $EnableBIOS) {
                Write-Log -Message "[VM: $($VMName)] [Planning] Would change Boot type to LEGACY" -Level Plan
                $VMSAlteredCountBoot ++
                if ($VM_vTPM -eq $true) {
                    Write-Log -Message "[VM: $($VMName)] [Planning] Would remove vTPM" -Level Plan
                    $VMSAlteredCountvTPM ++
                }
            }
            #------------------------------------------------------------
            # Handle vTPM
            #------------------------------------------------------------
            if ($AddVTPM -or $RemoveVTPM) {
                if ($VM_vTPM -eq $true) {
                    if ($RemoveVTPM) {
                        Write-Log -Message "[VM: $($VMName)] [Planning] Would remove vTPM " -Level Plan
                        $VMSAlteredCountvTPM ++
                    }
                } else {
                    if ($AddVTPM) {
                        Write-Log -Message "[VM: $($VMName)] [Planning] Would add vTPM " -Level Plan
                        $VMSAlteredCountvTPM ++
                    }
                }
            }

        } else {
            #We are executing

            #------------------------------------------------------------
            # Check Power State
            #------------------------------------------------------------
            if ($VM.spec.resources.power_state -ne "OFF") {
                Write-Log -Message "[VM: $($VMName)] VM is in power state $($VM.spec.resources.power_state). Will not process" -Level Warn
                $VMSNotAltered ++
                Continue
            }

            #------------------------------------------------------------
            # Export Current VM Config to File
            #------------------------------------------------------------
            $VM_Backup = $VM | ConvertTo-Json -Depth 9
            $VM_Config_Backup_Path = "$($LogPath | Split-Path)\VM_Config_Backup"
            if (-not (Test-Path -Path $VM_Config_Backup_Path)) {
                New-Item -Path $VM_Config_Backup_Path -ItemType Directory -Force | Out-Null
            }
            $VM_Backup_File = "$VM_Config_Backup_Path\$($VMName)_VM_Backup_$(Get-Date -Format ssmmhhddMMyyyy).json"
            $VM_Backup | Out-File -FilePath $VM_Backup_File -Force
            Write-Log -Message "[VM: $($VMName)] Exported VM Config to file: $VM_Backup_File" -Level Info

            #------------------------------------------------------------
            # Handle BIOS
            #------------------------------------------------------------
            if ($VM_Boot_Type -eq "LEGACY" -and $EnableUEFI) {
                Write-Log -Message "[VM: $($VMName)] Changing Boot type to UEFI" -Level Info
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Update the VM
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PUT"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                $BootType = "UEFI"

                $Initial_VM_Payload = $VM
                $Initial_VM_Payload.PSObject.Properties.Remove('status')
                $Initial_VM_Payload.spec.resources.boot_config.boot_type = $BootType

                $Payload = (ConvertTo-Json $Initial_VM_Payload -depth 9)
                #----------------------------------------------------------------------------------------------------------------------------
                $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get the task status
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                # Update the counts
                if ($Task_Status -eq "succeeded") { $VMSAlteredCountBoot ++ } else { $VMsFailedCount ++ ; Continue}

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get an updated view of the VM for the next stage
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

            }
            if ($VM_Boot_Type -eq "LEGACY" -and $EnableSecureBoot) {
                if ($VM_Has_IDE_CDROM -eq $true) {
                    Write-Log -Message "[VM: $($VMName)] Removing IDE CDROM from VM and setting machine type to q35" -Level Info
                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Update the VM - Remove the CD ROM
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "PUT"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"

                    $Initial_VM_Payload = $VM
                    $Initial_VM_Payload.PSObject.Properties.Remove('status')

                    $DiskList = @()
                    foreach ($Disk in $Initial_VM_Payload.spec.resources.disk_list) {
                        if ($Disk.device_properties.device_type -ne "CDROM" -and $Disk.device_properties.disk_address.adapter_type -ne "IDE") {
                            $DiskList += $Disk
                        }
                    }

                    $Initial_VM_Payload.spec.resources.disk_list = $DiskList
                    $Initial_VM_Payload.spec.resources.machine_type = "q35"

                    $Payload = (ConvertTo-Json $Initial_VM_Payload -depth 9)
                    #----------------------------------------------------------------------------------------------------------------------------
                    $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Get the task status
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "GET"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                    # Update the counts
                    if ($Task_Status -eq "succeeded") { $VMSAlteredCountCDROM ++ } else { $VMsFailedCount ++ ; Continue}

                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Get an updated view of the VM for the next stage
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "GET"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                    #----------------------------------------------------------------------------------------------------------------------------
                    $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials
                }
                Write-Log -Message "[VM: $($VMName)] Changing Boot type to SECURE_BOOT" -Level Info
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Update the VM
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PUT"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                $BootType = "SECURE_BOOT"

                $Initial_VM_Payload = $VM
                $Initial_VM_Payload.PSObject.Properties.Remove('status')
                $Initial_VM_Payload.spec.resources.boot_config.boot_type = $BootType

                $Payload = (ConvertTo-Json $Initial_VM_Payload -depth 9)
                #----------------------------------------------------------------------------------------------------------------------------
                $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get the task status
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                # Update the counts
                if ($Task_Status -eq "succeeded") { $VMSAlteredCountBoot ++ } else { $VMsFailedCount ++ ; Continue}

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get an updated view of the VM for the next stage
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

            }
            if ($VM_Boot_Type -eq "LEGACY" -and $EnableBIOS) {
                Write-Log -Message "[VM: $($VMName)] Is already configured as boot type LEGACY. Nothing to change" -Level Info
            }

            #------------------------------------------------------------
            # Handle UEFI
            #------------------------------------------------------------
            if ($VM_Boot_Type -eq "UEFI" -and $EnableUEFI) {
                Write-Log -Message "[VM: $($VMName)] Boot type is already UEFI. Nothing to change" -Level Info
            }
            if ($VM_Boot_Type -eq "UEFI" -and $EnableSecureBoot) {
                Write-Log -Message "[VM: $($VMName)] Changing Boot Boot type to SECURE_BOOT" -Level Info
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Update the VM
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PUT"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                $BootType = "SECURE_BOOT"

                $Initial_VM_Payload = $VM
                $Initial_VM_Payload.PSObject.Properties.Remove('status')
                $Initial_VM_Payload.spec.resources.boot_config.boot_type = $BootType

                $Payload = (ConvertTo-Json $Initial_VM_Payload -depth 9)
                #----------------------------------------------------------------------------------------------------------------------------
                $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get the task status
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                # Update the counts
                if ($Task_Status -eq "succeeded") { $VMSAlteredCountBoot ++ } else { $VMsFailedCount ++ ; Continue}

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get an updated view of the VM for the next stage
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

            }
            if ($VM_Boot_Type -eq "UEFI" -and $EnableBIOS) {
                # We need to remove the vTPM here - for ease of code, let's remove it first
                if ($VM_vTPM -eq $true) {
                    Write-Log -Message "[VM: $($VMName)] Handling vTPM Removal" -Level Info
                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Update the VM
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "PUT"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"

                    $Initial_VM_Payload = $VM
                    $Initial_VM_Payload.PSObject.Properties.Remove('status')

                    $New_VM_Payload = $Initial_VM_Payload | ConvertTo-Json -Depth 9 | ConvertFrom-Json -Depth 9

                    $New_VM_Payload.spec.resources = $New_VM_Payload.spec.resources | Select-Object * -ExcludeProperty vtpm_config

                    $Payload = (ConvertTo-Json $New_VM_Payload -depth 9)
                    #----------------------------------------------------------------------------------------------------------------------------
                    $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Get the task status
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "GET"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                    # Update the counts
                    if ($Task_Status -eq "succeeded") { $VMSAlteredCountBoot ++ } else { $VMsFailedCount ++ ; Continue}

                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Get an updated view of the VM for the next stage
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "GET"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                    #----------------------------------------------------------------------------------------------------------------------------
                    $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials
                }

                Write-Log -Message "[VM: $($VMName)] Changing Boot type to LEGACY" -Level Info
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Update the VM
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PUT"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                $BootType = "LEGACY"

                $Initial_VM_Payload = $VM
                $Initial_VM_Payload.PSObject.Properties.Remove('status')
                $Initial_VM_Payload.spec.resources.boot_config.boot_type = $BootType 

                $Payload = (ConvertTo-Json $Initial_VM_Payload -depth 9)
                #----------------------------------------------------------------------------------------------------------------------------
                $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get the task status
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                # Update the counts
                if ($Task_Status -eq "succeeded") { $VMSAlteredCountBoot ++ } else { $VMsFailedCount ++ ; Continue}

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get an updated view of the VM for the next stage
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials
            } 

            #------------------------------------------------------------
            # Handle Secure Boot
            #------------------------------------------------------------
            if ($VM_Boot_Type -eq "SECURE_BOOT" -and $EnableSecureBoot) {
                Write-Log -Message "[VM: $($VMName)] Boot type is already SECURE_BOOT. Nothing to change" -Level Info
            }
            if ($VM_Boot_Type -eq "SECURE_BOOT" -and $EnableUEFI) {
                Write-Log -Message "[VM: $($VMName)] Changing Boot type to UEFI" -Level Info
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Update the VM
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PUT"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                $BootType = "UEFI"

                $Initial_VM_Payload = $VM
                $Initial_VM_Payload.PSObject.Properties.Remove('status')
                $Initial_VM_Payload.spec.resources.boot_config.boot_type = $BootType

                $Payload = (ConvertTo-Json $Initial_VM_Payload -depth 9)
                #----------------------------------------------------------------------------------------------------------------------------
                $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get the task status
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                # Update the counts
                if ($Task_Status -eq "succeeded") { $VMSAlteredCountBoot ++ } else { $VMsFailedCount ++ ; Continue}

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get an updated view of the VM for the next stage
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

            }
            if ($VM_Boot_Type -eq "SECURE_BOOT" -and $EnableBIOS) {
                # We need to remove the vTPM here - for ease of code, let's remove it first
                if ($VM_vTPM -eq $true) {
                    Write-Log -Message "[VM: $($VMName)] Handling vTPM Removal" -Level Info
                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Update the VM
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "PUT"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"

                    $Initial_VM_Payload = $VM
                    $Initial_VM_Payload.PSObject.Properties.Remove('status')

                    $New_VM_Payload = $Initial_VM_Payload | ConvertTo-Json -Depth 9 | ConvertFrom-Json -Depth 9

                    $New_VM_Payload.spec.resources = $New_VM_Payload.spec.resources | Select-Object * -ExcludeProperty vtpm_config

                    $Payload = (ConvertTo-Json $New_VM_Payload -depth 9)
                    #----------------------------------------------------------------------------------------------------------------------------
                    $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Get the task status
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "GET"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                    # Update the counts
                    if ($Task_Status -eq "succeeded") { $VMSAlteredCountvTPM ++ } else { $VMsFailedCount ++ ; Continue}

                    #----------------------------------------------------------------------------------------------------------------------------
                    # Set API call detail - Get an updated view of the VM for the next stage
                    #----------------------------------------------------------------------------------------------------------------------------
                    $Method = "GET"
                    $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                    #----------------------------------------------------------------------------------------------------------------------------
                    $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials
                }

                Write-Log -Message "[VM: $($VMName)] Changing Boot type to LEGACY" -Level Info
                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Update the VM
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "PUT"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                $BootType = "LEGACY"

                $Initial_VM_Payload = $VM
                $Initial_VM_Payload.PSObject.Properties.Remove('status')
                $Initial_VM_Payload.spec.resources.boot_config.boot_type = $BootType

                $Payload = (ConvertTo-Json $Initial_VM_Payload -depth 9)
                #----------------------------------------------------------------------------------------------------------------------------
                $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get the task status
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                # Update the counts
                if ($Task_Status -eq "succeeded") { $VMSAlteredCountBoot ++ } else { $VMsFailedCount ++ ; Continue}

                #----------------------------------------------------------------------------------------------------------------------------
                # Set API call detail - Get an updated view of the VM for the next stage
                #----------------------------------------------------------------------------------------------------------------------------
                $Method = "GET"
                $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                #----------------------------------------------------------------------------------------------------------------------------
                $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials
            }

            #------------------------------------------------------------
            # Handle vTPM
            #------------------------------------------------------------
            if ($AddVTPM -or $RemoveVTPM) {
                # This is set again as we may have changed the VM object above - good house keeping to not assume
                $VM_vTPM = $VM.spec.resources.vtpm_config.vtpm_enabled
                if ($VM_vTPM -eq $true) {
                    Write-Log -Message "[VM: $($VMName)] Has a vTPM enabled" -Level Info
                    if ($RemoveVTPM) {
                        Write-Log -Message "[VM: $($VMName)] Handling vTPM Removal" -Level Info
                        #----------------------------------------------------------------------------------------------------------------------------
                        # Set API call detail - Update the VM
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Method = "PUT"
                        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"

                        $Initial_VM_Payload = $VM
                        $Initial_VM_Payload.PSObject.Properties.Remove('status')

                        $New_VM_Payload = $Initial_VM_Payload | ConvertTo-Json -Depth 9 | ConvertFrom-Json -Depth 9

                        $New_VM_Payload.spec.resources = $New_VM_Payload.spec.resources | Select-Object * -ExcludeProperty vtpm_config

                        $Payload = (ConvertTo-Json $New_VM_Payload -depth 9)
                        #----------------------------------------------------------------------------------------------------------------------------
                        $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                        #----------------------------------------------------------------------------------------------------------------------------
                        # Set API call detail - Get the task status
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Method = "GET"
                        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                        # Update the counts
                        if ($Task_Status -eq "succeeded") { $VMSAlteredCountvTPM ++ } else { $VMsFailedCount ++ ; Continue}

                        #----------------------------------------------------------------------------------------------------------------------------
                        # Set API call detail - Get an updated view of the VM for the next stage
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Method = "GET"
                        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                        #----------------------------------------------------------------------------------------------------------------------------
                        $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials
                    }
                } else {
                    Write-Log -Message "[VM: $($VMName)] Does not have a vTPM enabled" -Level Info
                    if ($AddVTPM) {
                        Write-Log -Message "[VM: $($VMName)] Handling vTPM Addition" -Level Info
                        #----------------------------------------------------------------------------------------------------------------------------
                        # Set API call detail - Update the VM
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Method = "PUT"
                        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"

                        $Initial_VM_Payload = $VM
                        $Initial_VM_Payload.PSObject.Properties.Remove('status')

                        $New_VM_Payload = $Initial_VM_Payload | ConvertTo-Json -Depth 9 | ConvertFrom-Json -Depth 9

                        # Create a new vTPM enabled Object
                        $add_vtpm = [PSCustomObject]@{
                            vtpm_enabled = $true
                        }

                        $New_VM_Payload.spec.resources | Add-Member -MemberType NoteProperty -Name 'vtpm_config' -Value $add_vtpm -Force

                        $Payload = (ConvertTo-Json $New_VM_Payload -depth 9)
                        #----------------------------------------------------------------------------------------------------------------------------
                        $VM_Update = InvokePrismAPI -Method $Method -Url $RequestUri -Payload $Payload -Credential $PrismCentralCredentials

                        #----------------------------------------------------------------------------------------------------------------------------
                        # Set API call detail - Get the task status
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Method = "GET"
                        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/tasks/$($VM_Update.status.execution_context.task_uuid)"
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Task_Status = Get-PrismCentralTask -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                        # Update the counts
                        if ($Task_Status -eq "succeeded") { $VMSAlteredCountvTPM ++ } else { $VMsFailedCount ++ ; Continue}

                        #----------------------------------------------------------------------------------------------------------------------------
                        # Set API call detail - Get an updated view of the VM for the next stage
                        #----------------------------------------------------------------------------------------------------------------------------
                        $Method = "GET"
                        $RequestUri = "https://$($pc_source):9440/api/nutanix/v3/vms/$($VM.metadata.uuid)"
                        #----------------------------------------------------------------------------------------------------------------------------
                        $VM = InvokePrismAPI -Method $Method -Url $RequestUri -Credential $PrismCentralCredentials

                    }
                }
            }
        }
    } else {
        Write-Log -Message "[VM: $($VMName)] Could not find VM $($VMName) in PC" -Level Warn
        continue
    }
}
#endregion Process VMs

#region Summary
Write-Log -Message "[Summary] Attempted to process $($VMToProcessCount) VMs" -Level Info
Write-Log -Message "[Summary] Successfully processed $($VMSAlteredCountBoot) VMs for Boot type changes" -Level Info
Write-Log -Message "[Summary] Successfully processed $($VMSAlteredCountvTPM) VMs for vTPM changes" -Level Info
Write-Log -Message "[Summary] Successfully processed $($VMSAlteredCountCDROM) VMs for CDROM changes" -Level Info
if ($VMsFailedCount -gt 0) {
    Write-Log -Message "[Summary] Failed to process $($VMsFailedCount) VMs" -Level Warn
}
Write-Log -Message "[Summary] $($VMSNotAltered) VMs were not altered " -Level Info
#endregion Summary

StopIteration
Exit 0
#endregion