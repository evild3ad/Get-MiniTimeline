# Get-MiniTimeline v0.2
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:	      https://lethal-forensics.com/
# @date:      2024-05-24
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
#
# Dependencies:
#
# KAPE v1.3.0.2 (2023-01-03)
# https://ericzimmerman.github.io/
# https://binaryforay.blogspot.com/search?q=KAPE
# https://www.kroll.com/kape
#
# EvtxECmd v1.5.0.0 (.NET 6)
# https://ericzimmerman.github.io/
# 
# MFTECmd v1.2.2.0 (.NET 6)
# https://ericzimmerman.github.io/
#
# RegRipper v3.0 (2020-05-28)
# https://github.com/keydet89/RegRipper3.0 (rip.exe, p2x5124.dll, plugins)
#
# TLN Tools
# https://github.com/mdegrazia/KAPE_Tools --> evtxECmd_2_tln.exe (2019-08-13), unicode_2_ascii.exe (2019-08-13)
# https://github.com/keydet89/Tools/tree/master/exe --> bodyfile.exe, evtparse.exe, p2x5124.dll, parse.exe, regtime.exe (2018-11-24)
#
# ImportExcel v7.8.9 (2024-05-18)
# https://github.com/dfinke/ImportExcel
#
#
# Changelog:
# Version 0.1
# Release Date: 2019-11-23
# Initial Release
#
# Version 0.2
# Release Date: 2024-05-24
# Added: Dependencies updated
# Added: Updating Event Log Maps
# Fixed: Other minor fixes and improvements
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  Get-MiniTimeline v0.2 - Triage Collection and Timeline Generation w/ KAPE

.DESCRIPTION
  Get-MiniTimeline.ps1 is a PowerShell script utilized to collect several forensic artifacts from a mounted forensic image and to auto-generate a MiniTimeline.

  Forensic Artifacts:
    - Master File Table ($MFT)
    - Windows Event Logs
    - Windows Registry

  USAGE: 1. Mount your forensic image with e.g. drive letter X: (\\.X:) --> $ROOT = X:
          Note: When your forensic image has multiple partitions you may have to change the path to the Windows partition.

         2. Run Windows PowerShell as Administrator.

.EXAMPLE
  PS > .\Get-MiniTimeline.ps1 dateRange:MM/DD/YYYY-MM/DD/YYYY

.NOTES
  Author - Martin Willing (@Evild3ad79)

.LINK
  https://lethal-forensics.com/

#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$OriginalProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Input (Source)
# Example: Mount your forensic image with e.g. drive letter X: (\\.X:) --> $ROOT = X:
# Note: When your forensic image has multiple partitions you may have to change the path to the Windows partition.
$ROOT = "G:"

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Tools

# EvtxECmd
$script:EvtxECmd = "$SCRIPT_DIR\Modules\bin\EvtxECmd\EvtxECmd.exe"

# KAPE
$script:KAPE = "$SCRIPT_DIR\kape.exe"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "Get-MiniTimeline v0.2 - Triage Collection and Timeline Generation w/ KAPE"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check if the PowerShell script is being run in Windows PowerShell ISE
if ("$($psISE)")
{
    Write-Host "[Error] This PowerShell script must be run in Windows PowerShell." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Add the required MessageBox class
Add-Type -AssemblyName System.Windows.Forms

# Add the required Graphics class
Add-Type -AssemblyName System.Drawing

# ImportRegistryHive.psm1 by Chris Redit
# https://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html

# Function Import-RegistryHive
Function Import-RegistryHive
{
    <#
    .SYNOPSIS
        Import a registry hive from a file.
    .DESCRIPTION
        Import a registry hive from a file. An imported hive is loaded into a named PSDrive available globally in the current session.
    .EXAMPLE
        C:\PS>Import-RegistryHive -File 'C:\Users\Default\NTUSER.DAT' -Key 'HKLM\TEMP_HIVE' -Name TempHive
        C:\PS>Get-ChildItem TempHive:\
    .PARAMETER File
        The registry hive file to load, eg. NTUSER.DAT
    .PARAMETER Key
        The registry key to load the hive into, in the format HKLM\MY_KEY or HKCU\MY_KEY
    .PARAMETER Name
        The name of the PSDrive to access the hive, excluding the characters ;~/\.:
    .OUTPUTS
        $null or Exception on error
    #>

    Param(
        [String][Parameter(Mandatory=$true)]$File,
        [String][Parameter(Mandatory=$true)][ValidatePattern('^(HKLM\\|HKCU\\)[a-zA-Z0-9- _\\]+$')]$Key,
        [String][Parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )

    # Check whether the drive name is available
    $TestDrive = Get-PSDrive -Name $Name -EA SilentlyContinue
    if ($null -ne $TestDrive)
    {
        $ErrorRecord = New-Object Management.Automation.ErrorRecord(
            (New-Object Management.Automation.SessionStateException("A drive with the name '$Name' already exists.")),
            'DriveNameUnavailable', [Management.Automation.ErrorCategory]::ResourceUnavailable, $null
        )
        $PSCmdlet.ThrowTerminatingError($ErrorRecord)
    }

    # Load the Registry Hive using reg.exe
    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load $Key $File" -WindowStyle Hidden -PassThru -Wait
    
    if ($Process.ExitCode)
    {
        $ErrorRecord = New-Object Management.Automation.ErrorRecord(
            (New-Object Management.Automation.PSInvalidOperationException("The registry hive '$File' failed to load. Verify the source path or target registry key.")),
            'HiveLoadFailure', [Management.Automation.ErrorCategory]::ObjectNotFound, $null
        )
        $PSCmdlet.ThrowTerminatingError($ErrorRecord)
    }

    try
    {
        # Create a global drive using the registry provider, with the root path as the previously loaded registry hive
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null
    }
    catch
    {
        # Validate patten on $Name in the Params and the drive name check at the start make it very unlikely New-PSDrive will fail
        $ErrorRecord = New-Object Management.Automation.ErrorRecord(
            (New-Object Management.Automation.PSInvalidOperationException("An unrecoverable error creating drive '$Name' has caused the registy key '$Key' to be left loaded, this must be unloaded manually.")),
            'DriveCreateFailure', [Management.Automation.ErrorCategory]::InvalidOperation, $null
        )
        $PSCmdlet.ThrowTerminatingError($ErrorRecord);
    }
}

# Function Remove-RegistryHive
Function Remove-RegistryHive
{
    <#
    .SYNOPSIS
        Remove a registry hive loaded via Import-RegistryHive.
    .DESCRIPTION
        Remove a registry hive loaded via Import-RegistryHive. Removing the the hive will remove the associated PSDrive and unload the registry key created during the import.
    .EXAMPLE
        C:\PS>Remove-RegistryHive -Name TempHive
    .PARAMETER Name
        The name of the PSDrive used to access the hive.
    .OUTPUTS
        $null or Exception on error
    #>

    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )

    # Get the drive that was used to map the Registry Hive
    $Drive = Get-PSDrive -Name $Name -ErrorAction SilentlyContinue

    # If $Drive is $null the drive name was incorrect
    if ($null -eq $Drive)
    {
        $ErrorRecord = New-Object Management.Automation.ErrorRecord(
            (New-Object Management.Automation.DriveNotFoundException("The drive '$Name' does not exist.")),
            'DriveNotFound', [Management.Automation.ErrorCategory]::ResourceUnavailable, $null
        )
        $PSCmdlet.ThrowTerminatingError($ErrorRecord)
    }

    # $Drive.Root is the path to the registry key, save this before the drive is removed
    $Key = $Drive.Root

    try
    {
        # Remove the drive, the only reason this should fail is if the resource is busy
        Remove-PSDrive $Name -EA Stop
    }
    catch
    {
        $ErrorRecord = New-Object Management.Automation.ErrorRecord(
            (New-Object Management.Automation.PSInvalidOperationException("The drive '$Name' could not be removed, it may still be in use.")),
            'DriveRemoveFailure', [Management.Automation.ErrorCategory]::ResourceBusy, $null
        )
        $PSCmdlet.ThrowTerminatingError($ErrorRecord)
    }

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload $Key" -WindowStyle Hidden -PassThru -Wait
    
    if ($Process.ExitCode)
    {
        # If "reg unload" fails due to the resource being busy, the drive gets added back to keep the original state
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -EA Stop | Out-Null

        $ErrorRecord = New-Object Management.Automation.ErrorRecord(
            (New-Object Management.Automation.PSInvalidOperationException("The registry key '$Key' could not be unloaded, it may still be in use.")),
            'HiveUnloadFailure', [Management.Automation.ErrorCategory]::ResourceBusy, $null
        )
        $PSCmdlet.ThrowTerminatingError($ErrorRecord)
    }
}

# Function Get-FileSize
Function Get-FileSize()
{
    Param ([long]$Length)
    If ($Length -gt 1TB) {[string]::Format("{0:0.00} TB", $Length / 1TB)}
    ElseIf ($Length -gt 1GB) {[string]::Format("{0:0.00} GB", $Length / 1GB)}
    ElseIf ($Length -gt 1MB) {[string]::Format("{0:0.00} MB", $Length / 1MB)}
    ElseIf ($Length -gt 1KB) {[string]::Format("{0:0.00} KB", $Length / 1KB)}
    ElseIf ($Length -gt 0) {[string]::Format("{0:0.00} Bytes", $Length)}
    Else {""}
}

# EZTools
if (Get-Command -CommandType Application dotnet -ErrorAction SilentlyContinue)
{
    # TargetFramework (.NET 6)
    if (!(dotnet --list-runtimes | Select-String -Pattern "^Microsoft\.WindowsDesktop\.App" -Quiet))
    {
        Write-Host "[Error] Please download/install at least .NET 6.0 or newer manually:" -ForegroundColor Red
        Write-Host "        https://dotnet.microsoft.com/en-us/download/dotnet/6.0 (Recommended: .NET Desktop Runtime)" -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    Write-Host "[Error] Please download/install at least .NET 6.0 or newer manually:" -ForegroundColor Red
    Write-Host "        https://dotnet.microsoft.com/en-us/download/dotnet/6.0 (Recommended: .NET Desktop Runtime)" -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check if PowerShell module 'ImportExcel' exists
if (!(Get-Module -ListAvailable -Name ImportExcel))
{
    Write-Host "[Error] PowerShell module 'ImportExcel' NOT found." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# ComputerName
Import-RegistryHive -File "$ROOT\Windows\System32\config\SYSTEM" -Key "HKLM\TEMP_SYSTEM" -Name SystemHive
$CurrentControlSet = Get-ItemPropertyValue "SystemHive:\Select" -Name Current
$ComputerName = Get-ItemPropertyValue "SystemHive:\ControlSet00$CurrentControlSet\Control\ComputerName\ComputerName" -Name ComputerName
Remove-RegistryHive -Name SystemHive

# Output Directory
$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\MiniTimeline\$ComputerName"

# Flush Output Directory
if (Test-Path $OUTPUT_FOLDER)
{
    Get-ChildItem -Path "$OUTPUT_FOLDER" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}
else
{
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}

# Create a record of your Windows PowerShell session to a text file
Start-Transcript -Path "$OUTPUT_FOLDER\Transcript.txt"

# Get Start Time
$startTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

# Header
Write-Output "Get-MiniTimeline v0.2 - Triage Collection and Timeline Generation w/ KAPE"
Write-Output "(c) 2024 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$script:AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region KAPE

# Kroll Artifact Parser and Extractor (KAPE)

# Input-Check
if (!(Test-Path "$ROOT\Windows"))
{
    Write-Host "[Error] Drive Letter does not exist or is no Windows partition." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Parameter
$dateRange=$args[0]

# Check if an argument was entered
if ($dateRange)
{
    # Check if the correct argument was entered
    if ($dateRange -like "*dateRange*")
    {
        # Check if a valid Date Range was provided
        if (-not($dateRange -match "^dateRange:[0-9]{2}/[0-9]{2}/[0-9]{4}-[0-9]{2}/[0-9]{2}/[0-9]{4}$"))
        {
            Write-Host "[Error] Please provide a correct Date Range: dateRange:MM/DD/YYYY-MM/DD/YYYY" -ForegroundColor Red
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
    else
    {
        Write-Host "[Error] The entered parameter doesn't exist. The optional parameter is: dateRange:MM/DD/YYYY-MM/DD/YYYY" -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    Write-Host "[Error] Please provide a Date Range: dateRange:MM/DD/YYYY-MM/DD/YYYY" -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# EvtxECmd
Function Update-EvtxECmd {

    # Internet Connectivity Check (Vista+)
    $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

    if (!($NetworkListManager -eq "True"))
    {
         Write-Host "[Error] Your computer is NOT connected to the Internet. Event Log Maps cannot be updated." -ForegroundColor Red
    }
    else
    {
        # Check if GitHub is reachable
        if (!(Test-NetConnection -ComputerName github.com -Port 443).TcpTestSucceeded)
        {
            Write-Host "[Error] github.com is NOT reachable. Event Log Maps cannot be updated." -ForegroundColor Red
        }
        else
        {
            Write-Output "[Info]  Updating Event Log Maps ... "

            # Flush
            if (Test-Path "$SCRIPT_DIR\Modules\bin\EvtxECmd\Maps")
            {
                Get-ChildItem -Path "$SCRIPT_DIR\Modules\bin\EvtxECmd\Maps" -Recurse | Remove-Item -Force -Recurse
            }

            # Sync for EvtxECmd Maps with GitHub
            if (Test-Path "$($EvtxECmd)")
            {
                & $EvtxECmd --sync > "$SCRIPT_DIR\Modules\bin\EvtxECmd\Maps.log" 2> $null
            }
            else
            {
                Write-Host "[Error] EvtxECmd.exe NOT found." -ForegroundColor Red
            }
        }
    }
}

Update-EvtxECmd

# Check for required .NET Framework 4.5 and later
if ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 394802)
{
    if (Test-Path "$($KAPE)")
    {
        # Mini Timeline Collection
        Write-Host "[Info]  Collecting Master File Table (`$MFT), Registry and Event Logs ... "
        New-Item "$OUTPUT_FOLDER\Mini_Timeline_Collection" -ItemType Directory -Force 2>&1 | Out-Null
        & $KAPE --tsource $ROOT --tdest "$OUTPUT_FOLDER\Mini_Timeline_Collection" --target MiniTimelineCollection --tdd False 2>&1 | Out-Null

        # Stats
        $Total = (Get-Content "$OUTPUT_FOLDER\Mini_Timeline_Collection\*_CopyLog.csv" | Measure-Object).Count -1
        $Size = "{0:N2} MB" -f ((Get-ChildItem –Force "$OUTPUT_FOLDER\Mini_Timeline_Collection" –Recurse -ErrorAction SilentlyContinue| Measure-Object Length -s).Sum / 1MB)
        if (($Total) -And ($Size)) { Write-Host "[Info]  $Total File(s) copied ($Size)" }

        # Module: Mini_Timeline (TLN format)
        Write-Host "[Info]  Creating Mini_Timeline w/ KAPE [approx. 2-6 min] ... "
        New-Item "$OUTPUT_FOLDER\Mini_Timeline" -ItemType Directory -Force 2>&1 | Out-Null

        # Module: Mini_Timeline_Slice_by_Daterange (TLN format)
        if (($dateRange) -And ($dateRange -like "*dateRange*"))
        {
            # Targeted Timeline Creation
            & $KAPE --msource "$OUTPUT_FOLDER\Mini_Timeline_Collection" --mdest "$OUTPUT_FOLDER\Mini_Timeline" --mflush --module Mini_Timeline,Mini_Timeline_Slice_by_Daterange --mvars "computerName:$ComputerName^$dateRange" 2>&1 | Out-Null
        }
        else
        {
            # Automated Timeline Creation
            & $KAPE --msource "$OUTPUT_FOLDER\Mini_Timeline_Collection" --mdest "$OUTPUT_FOLDER\Mini_Timeline" --mflush --module Mini_Timeline --mvars computerName:$ComputerName 2>&1 | Out-Null
        }

        # Full Timeline File Size (CSV) --> Timeline Explorer (TLE)
        if (Test-Path "$OUTPUT_FOLDER\Mini_Timeline\Timeline\01_timeline.csv")
        {
            $File = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\01_timeline.csv"
            $Size = Get-FileSize((Get-Item $File).Length)
            Write-Host "[Info]  Full Timeline File Size: $Size"
        }

        # Slice File Size (CSV)
        if (Test-Path "$OUTPUT_FOLDER\Mini_Timeline\Timeline\01_timeline_dateRange.csv")
        {
            $File = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\01_timeline_dateRange.csv"
            $Size = Get-FileSize((Get-Item $File).Length)
            Write-Host "[Info]  Slice File Size: $Size"
        }

        # Stats
        $Total = (Get-ChildItem –Force "$OUTPUT_FOLDER\Mini_Timeline\Timeline" -Exclude "temp*" | Measure-Object).Count
        $Size = "{0:N2} MB" -f ((Get-ChildItem –Force "$OUTPUT_FOLDER\Mini_Timeline\Timeline" –Recurse -ErrorAction SilentlyContinue| Measure-Object Length -s).Sum / 1MB)
        if (($Total) -And ($Size)) { Write-Host "[Info]  $Total Timeline file(s) created ($Size)" }

        # Windows Title
        $Host.UI.RawUI.WindowTitle = "Get-MiniTimeline v0.2 - Triage Collection and Timeline Generation w/ KAPE"

        Write-Host "[Info]  Beautifying Timelines for Analysis ... "

        # Add Header Line (Timeline_Slice)
        $ImportFile = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\Timeline_Slice.csv"
        $ImportFileNoHeader = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\01_timeline_dateRange.csv"
        Clear-Content $ImportFile 2>&1 | Out-Null
        Add-Content $ImportFile “Time,Source,Host,User,Description”
        Get-Content $ImportFileNoHeader | Add-Content $ImportFile

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel) 
        {
            New-Item "$OUTPUT_FOLDER\Mini_Timeline\Timeline\XLSX" -ItemType Directory -Force | Out-Null
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\Mini_Timeline\Timeline\Timeline_Slice.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Mini_Timeline\Timeline\XLSX\Timeline_Slice.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Timeline_Slice" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            # Source: FILE --> Dark Green
            $FileColor = [System.Drawing.Color]::FromArgb(0,176,80)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$B1="FILE"' -BackgroundColor $FileColor
            # Source: REG --> Yellow
            $RegColor = [System.Drawing.Color]::FromArgb(255,255,0)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$B1="REG"' -BackgroundColor $RegColor
            # Source: EVT --> Grey
            $EvtxColor = [System.Drawing.Color]::FromArgb(217,217,217)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$B1="EVTX"' -BackgroundColor $EvtxColor
            # Source: ALERT --> Light Blue
            $AlertColor = [System.Drawing.Color]::FromArgb(0,176,240)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$B1="ALERT"' -BackgroundColor $AlertColor
            # Malicious: McAfee Quarantine Files (.bup) --> Red
            $MaliciousColor = [System.Drawing.Color]::FromArgb(255,0,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND(".bup",$E1)))' -BackgroundColor $MaliciousColor
            }

            # Slice File Size (CSV)
            if (Test-Path "$OUTPUT_FOLDER\Mini_Timeline\Timeline\XLSX\Timeline_Slice.xlsx")
            {
                $File = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\XLSX\Timeline_Slice.xlsx"
                $Size = Get-FileSize((Get-Item $File).Length)
                Write-Host "[Info]  Slice File Size (XLSX): $Size"
            }
        }

        # Add Header Line (Timeline_dateRange)
        $ImportFile = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\Timeline_dateRange.csv"
        $ImportFileNoHeader = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\01_timeline_dateRange.csv"
        Clear-Content $ImportFile 2>&1 | Out-Null
        Add-Content $ImportFile “Time,Source,Host,User,Description”
        Get-Content $ImportFileNoHeader | Add-Content $ImportFile

        # Add Header Line (Timeline)
        $ImportFile = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\Timeline.csv"
        $ImportFileNoHeader = "$OUTPUT_FOLDER\Mini_Timeline\Timeline\01_timeline.csv"
        Clear-Content $ImportFile 2>&1 | Out-Null
        Add-Content $ImportFile “Time,Source,Host,User,Description”
        Get-Content $ImportFileNoHeader | Add-Content $ImportFile
    }
    else
    {
        Write-Host "[Error] kape.exe NOT found." -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    Write-Host "[Error] KAPE requires Microsoft .NET Framework 4.5 or later." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

#endregion KAPE

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Host ""
Write-Host "FINISHED!"
'Overall analysis duration: {0:hh} h {0:mm} min {0:ss} sec' -f ($endTime-$startTime)

# Stop logging
Write-Host ""
Stop-Transcript
Start-Sleep 2

# MessageBox UI
$MessageBody = "Status: MiniTimeline Creation completed."
$MessageTitle = "Get-MiniTimeline.ps1 (https://lethal-forensics.com/)"
$ButtonType = "OK"
$MessageIcon = "Information"
$Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

if ($Result -eq "OK" ) 
{
    # Reset Progress Preference
    $Global:ProgressPreference = $OriginalProgressPreference

    # Reset Windows Title
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

#endregion Footer

#############################################################################################################################################################################################

# Investigation Notes

# TLN Timeline Format
# Time|Source|Host|User|Description

# Time: 32 Bit Unix Epoch
# Source: EVT, REG, FILE, etc.
# Host: Computer Name, IP address, etc.
# User: Username, SID, IM Screen name, etc.
# Description: Description of event

# Colors (Legend):
#
# Source (Source Category only):
# - FILE  --> Dark Green (0,176,80)  / FontColor Black
# - REG   --> Yellow (255,255,0)     / FontColor Black
# - ALERT --> Light Blue (0,176,240) / FontColor Black
# - EVT   --> Grey (217,217,217)     / FontColor Black
# - ???
#
# Bookmarks (Row):
# - Malicious  --> Red (255,0,0)      / FontColor Black
# - Suspicious --> Orange (255,192,0) / FontColor Black

#############################################################################################################################################################################################

# Links
# http://az4n6.blogspot.com/2019/08/triage-collection-and-timeline.html
# https://windowsir.blogspot.com/2009/02/timeline-analysis.html
# https://digital-forensics.sans.org/blog/2012/01/25/digital-forensic-sifting-colorized-super-timeline-template-for-log2timeline-output-files/
# https://www.sans.org/blog/triage-collection-and-timeline-generation-with-kape/
# https://www.youtube.com/watch?v=O5VW0Yr7guQ
# https://www.kroll.com/-/media/kroll/pdfs/webinars/artifact-analysis-timelining-with-kape.pdf
