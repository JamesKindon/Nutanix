<#
.SYNOPSIS
    Audits and configures Windows power settings to guarantee reliable ACPI graceful shutdowns.
.DESCRIPTION
    Applies or audits configurations detailed in Nutanix KB kA00e000000LJZSCA4 (KB 5828):
    Item 1: Disables screensavers system-wide and sets display timeout to 'Never'.
    Item 2: Sets the hardware/virtual power button event to trigger a system 'Shut down'.
    Item 3: Ensures the Windows 'Power' service is set to Automatic and running.
.PARAMETER ReportOnly
    When specified, the script only audits and displays the current state of the VM. No changes are applied.
.PARAMETER WhatIf
    Standard PowerShell parameter. Simulates actions the script would take without making changes.
.EXAMPLE
    .\Set-AcpiPowerSettings.ps1 -ReportOnly
    .\Set-AcpiPowerSettings.ps1 -WhatIf
    .\Set-AcpiPowerSettings.ps1
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$ReportOnly
)

# Well-known powercfg GUIDs (stable across Windows builds and locales).
$VIDEO_SUBGROUP = '7516b95f-f776-4464-8c53-06167f40cc99'   # Display
$VIDEO_IDLE     = '3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'   # Turn off display after
$BTN_SUBGROUP   = '4f971e89-eebd-4455-a8de-9e59040e7347'   # Power buttons and lid
$BTN_PWR_ACTION = '7648efa3-dd9c-4e3e-b566-50f929386280'   # Power button action (3 = Shut down)

# Tracks whether any apply step failed so the final banner is honest.
$script:ChangeFailed = $false

# 0. Check for Administrative Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "CRITICAL: This script must be run as an Administrator. Please relaunch PowerShell as an Administrator."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Nutanix AHV ACPI Graceful Shutdown Configuration Tool  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------
# Helper Function: Parse powercfg configuration safely across languages
# ---------------------------------------------------------------------
function Get-PowerSettingIndex {
    param([string]$SubgroupGuid, [string]$SettingGuid)
    # powercfg output is localized, so do NOT key off English label text.
    # Collect every hex (0x...) token. The Current AC then Current DC index
    # are always the LAST two hex values emitted; any Minimum/Maximum/increment
    # "Possible Setting" hex values precede them. GUID lines use dashed form
    # (no 0x) so are never matched. Locale-independent.
    $output = powercfg /q SCHEME_CURRENT $SubgroupGuid $SettingGuid 2>$null
    $indices = @(
        foreach ($line in $output) {
            if ($line -match '0x([0-9a-fA-F]+)') { [Convert]::ToInt64($Matches[1], 16) }
        }
    )
    [PSCustomObject]@{
        AC = if ($indices.Count -ge 2) { $indices[-2] } else { $null }
        DC = if ($indices.Count -ge 1) { $indices[-1] } else { $null }
    }
}

# ---------------------------------------------------------------------
# PHASE 1: GATHER CURRENT STATE
# ---------------------------------------------------------------------
Write-Host "`n[Phase 1] Auditing current system settings..." -ForegroundColor Yellow

# Item 1 Variables
# NOTE: HKCU reflects only the account running this script (e.g. the admin
# context). For a VDI gold image the HKLM policy below is the enforcing
# setting; the HKCU write is best-effort for the current profile.
$hkcuScreensaver = (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
$hklmScreensaver = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveActive" -ErrorAction SilentlyContinue).ScreenSaveActive
$monitorSettings = Get-PowerSettingIndex -SubgroupGuid $VIDEO_SUBGROUP -SettingGuid $VIDEO_IDLE

# Item 2 Variables
# The "Power button action" (PBUTTONACTION) setting is hidden by default,
# especially on VMs. Unhide it so it can be queried and set; otherwise
# powercfg returns no AC/DC index and the value reads blank.
powercfg -attributes $BTN_SUBGROUP $BTN_PWR_ACTION -ATTRIB_HIDE 2>$null | Out-Null
$powerButtonSettings = Get-PowerSettingIndex -SubgroupGuid $BTN_SUBGROUP -SettingGuid $BTN_PWR_ACTION

# Item 3 Variables
$powerService = Get-Service -Name "Power" -ErrorAction SilentlyContinue

# Display Audit Report
Write-Host "`n--- CURRENT CONFIGURATION REPORT ---" -ForegroundColor Gray

# Report Item 1
if ($hkcuScreensaver -eq "0") { Write-Host "  [Item 1] HKCU Screensaver:         Disabled (Compliant)" -ForegroundColor Green }
else { Write-Host "  [Item 1] HKCU Screensaver:         Enabled or Not Configured (Non-Compliant)" -ForegroundColor Red }

if ($hklmScreensaver -eq "0") { Write-Host "  [Item 1] HKLM Screensaver Policy:  Enforced Disabled (Compliant)" -ForegroundColor Green }
else { Write-Host "  [Item 1] HKLM Screensaver Policy:  Not Enforced (Non-Compliant)" -ForegroundColor Red }

if ($monitorSettings.AC -eq 0) { Write-Host "  [Item 1] Monitor Timeout (AC):     Never (Compliant)" -ForegroundColor Green }
else { Write-Host "  [Item 1] Monitor Timeout (AC):     $($monitorSettings.AC) seconds (Non-Compliant)" -ForegroundColor Red }

if ($monitorSettings.DC -eq 0) { Write-Host "  [Item 1] Monitor Timeout (DC):     Never (Compliant)" -ForegroundColor Green }
else { Write-Host "  [Item 1] Monitor Timeout (DC):     $($monitorSettings.DC) seconds (Non-Compliant)" -ForegroundColor Red }

# Report Item 2
if ($powerButtonSettings.AC -eq 3) { Write-Host "  [Item 2] Power Button Action (AC): Shut down (Compliant)" -ForegroundColor Green }
else { Write-Host "  [Item 2] Power Button Action (AC): Modified Index: $($powerButtonSettings.AC) (Non-Compliant)" -ForegroundColor Red }

if ($powerButtonSettings.DC -eq 3) { Write-Host "  [Item 2] Power Button Action (DC): Shut down (Compliant)" -ForegroundColor Green }
else { Write-Host "  [Item 2] Power Button Action (DC): Modified Index: $($powerButtonSettings.DC) (Non-Compliant)" -ForegroundColor Red }

# Report Item 3
if (-not $powerService) {
    Write-Host "  [Item 3] Windows Power Service:    Not found (Non-Compliant)" -ForegroundColor Red
} elseif ($powerService.StartType -eq "Automatic" -and $powerService.Status -eq "Running") {
    Write-Host "  [Item 3] Windows Power Service:    Automatic & Running (Compliant)" -ForegroundColor Green
} else {
    Write-Host "  [Item 3] Windows Power Service:    Startup: $($powerService.StartType), Status: $($powerService.Status) (Non-Compliant)" -ForegroundColor Red
}

# Exit early if user requested ReportOnly
if ($ReportOnly) {
    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host " Audit Complete. No modifications made (-ReportOnly active)." -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    exit 0
}

# ---------------------------------------------------------------------
# PHASE 2: APPLY CHANGES (with WhatIf / ShouldProcess support)
# ---------------------------------------------------------------------
Write-Host "`n[Phase 2] Evaluating and enforcing system optimizations..." -ForegroundColor Yellow

# Helper: run a native powercfg command and flag failures via exit code.
function Invoke-PowerCfg {
    param([Parameter(Mandatory)][string[]]$Arguments, [string]$Context)
    & powercfg.exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "powercfg failed ($Context). Exit code: $LASTEXITCODE"
        $script:ChangeFailed = $true
    }
}

# Fix Item 1: Screensaver settings
if ($hkcuScreensaver -ne "0") {
    if ($PSCmdlet.ShouldProcess("Registry (HKCU:\Control Panel\Desktop)", "Set ScreenSaveActive to 0")) {
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "0" -ErrorAction SilentlyContinue
    }
}
if ($hklmScreensaver -ne "0") {
    if ($PSCmdlet.ShouldProcess("Registry Policy (HKLM:\SOFTWARE\Policies\Microsoft\...)", "Create and set ScreenSaveActive Policy to 0")) {
        $PolicyReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
        try {
            if (-not (Test-Path $PolicyReg)) { New-Item -Path $PolicyReg -Force -ErrorAction Stop | Out-Null }
            Set-ItemProperty -Path $PolicyReg -Name "ScreenSaveActive" -Value "0" -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "Failed to enforce HKLM screensaver policy: $($_.Exception.Message)"
            $script:ChangeFailed = $true
        }
    }
}
if ($monitorSettings.AC -ne 0) {
    if ($PSCmdlet.ShouldProcess("Power Configuration (AC Plan)", "Set Monitor Timeout to 0 (Never)")) {
        Invoke-PowerCfg -Arguments @('/change', 'monitor-timeout-ac', '0') -Context "monitor-timeout-ac"
    }
}
if ($monitorSettings.DC -ne 0) {
    if ($PSCmdlet.ShouldProcess("Power Configuration (DC Plan)", "Set Monitor Timeout to 0 (Never)")) {
        Invoke-PowerCfg -Arguments @('/change', 'monitor-timeout-dc', '0') -Context "monitor-timeout-dc"
    }
}

# Fix Item 2: Power Button Mappings
if ($powerButtonSettings.AC -ne 3) {
    if ($PSCmdlet.ShouldProcess("Power Settings (AC Button)", "Map Power Button Action to 3 (Shut down)")) {
        Invoke-PowerCfg -Arguments @('/setacvalueindex', 'SCHEME_CURRENT', $BTN_SUBGROUP, $BTN_PWR_ACTION, '3') -Context "power button (AC)"
        Invoke-PowerCfg -Arguments @('/setactive', 'SCHEME_CURRENT') -Context "setactive (AC)"
    }
}
if ($powerButtonSettings.DC -ne 3) {
    if ($PSCmdlet.ShouldProcess("Power Settings (DC Button)", "Map Power Button Action to 3 (Shut down)")) {
        Invoke-PowerCfg -Arguments @('/setdcvalueindex', 'SCHEME_CURRENT', $BTN_SUBGROUP, $BTN_PWR_ACTION, '3') -Context "power button (DC)"
        Invoke-PowerCfg -Arguments @('/setactive', 'SCHEME_CURRENT') -Context "setactive (DC)"
    }
}

# Fix Item 3: Windows Power Service
if (-not $powerService) {
    Write-Warning "Windows 'Power' service not found; cannot configure (Item 3)."
    $script:ChangeFailed = $true
} else {
    if ($powerService.StartType -ne "Automatic") {
        if ($PSCmdlet.ShouldProcess("Windows Service (Power)", "Change Startup type to 'Automatic'")) {
            try { Set-Service -Name "Power" -StartupType Automatic -ErrorAction Stop }
            catch { Write-Warning "Failed to set Power service to Automatic: $($_.Exception.Message)"; $script:ChangeFailed = $true }
        }
    }
    if ($powerService.Status -ne "Running") {
        if ($PSCmdlet.ShouldProcess("Windows Service (Power)", "Start the service")) {
            try { Start-Service -Name "Power" -ErrorAction Stop }
            catch { Write-Warning "Failed to start Power service: $($_.Exception.Message)"; $script:ChangeFailed = $true }
        }
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
if ($WhatIfPreference) {
    Write-Host " Simulation Complete. No real changes were committed." -ForegroundColor Yellow
} elseif ($script:ChangeFailed) {
    Write-Host " Completed WITH ERRORS. Re-run with -ReportOnly to verify; some settings were not applied." -ForegroundColor Red
} else {
    Write-Host " Execution Complete. Target system matches optimization profile." -ForegroundColor Green
}
Write-Host "==========================================================" -ForegroundColor Cyan
