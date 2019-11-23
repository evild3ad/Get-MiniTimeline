<#
.SYNOPSIS
Get-MiniTimeline v0.1 - Triage Collection and Timeline Generation w/ KAPE

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
https://www.evild3ad.com/

#>

#############################################################################################################################################################################################

# Get-MiniTimeline v0.1
#
# @author:    evild3ad
# @license:   MIT License
# @copyright: Copyright (c) 2019 Martin Willing.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@evild3ad.com
# @url:		  https://evild3ad.com/
# @date:	  2019-11-16
#
#              _ _     _ _____           _ 
#    _____   _(_) | __| |___ /  __ _  __| |
#   / _ \ \ / / | |/ _` | |_ \ / _` |/ _` |
#  |  __/\ V /| | | (_| |___) | (_| | (_| |
#   \___| \_/ |_|_|\__,_|____/ \__,_|\__,_|
#
#
#
# Dependencies:
#
# KAPE v0.8.8.0 (2019-10-23)
# https://ericzimmerman.github.io/
# https://binaryforay.blogspot.com/search?q=KAPE
#
# EvtxECmd v0.5.2.0 (2019-08-26)
# https://ericzimmerman.github.io/
# 
# MFTECmd v0.4.4.6 (2019-08-30)
# https://ericzimmerman.github.io/
#
# RegRipper v2.8 (2019-08-14)
# https://github.com/keydet89/RegRipper2.8 (rip.exe, p2x5124.dll, plugins)
#
# TLN Tools
# https://github.com/mdegrazia/KAPE_Tools --> evtxECmd_2_tln.exe (2019-08-13), unicode_2_ascii.exe (2019-08-13)
# https://github.com/keydet89/Tools/tree/master/exe --> bodyfile.exe, evtparse.exe, p2x5124.dll, parse.exe, regtime.exe (2018-11-24)
#
# ImportExcel 6.5.2
# https://github.com/dfinke/ImportExcel
#
# ImportRegistryHive.psm1 by Chris Redit
# https://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html

#############################################################################################################################################################################################

# Input (Source)
# Example: Mount your forensic image with e.g. drive letter X: (\\.X:) --> $ROOT = X:
# Note: When your forensic image has multiple partitions you may have to change the path to the Windows partition.
$ROOT = "G:"

#############################################################################################################################################################################################

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
$KAPE = "$SCRIPT_DIR\kape.exe"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
Exit
}

# Check if the PowerShell script is being run in Windows PowerShell ISE
if ($psISE)
{
Write-Host "[Error] This PowerShell script must be run in Windows PowerShell." -ForegroundColor Red
Exit
}

# Input-Check
if (!(Test-Path "$ROOT\Windows"))
{
Write-Host "[Error] Drive Letter does not exist or is no Windows partition." -ForegroundColor Red
Exit
}

#############################################################################################################################################################################################

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
        Exit
        }
    }
    else
    {
    Write-Host "[Error] The entered parameter doesn't exist. The optional parameter is: dateRange:MM/DD/YYYY-MM/DD/YYYY" -ForegroundColor Red
    Exit
    }
}
else
{
Write-Host "[Error] Please provide a Date Range: dateRange:MM/DD/YYYY-MM/DD/YYYY" -ForegroundColor Red
Exit
}

#############################################################################################################################################################################################

# Check if PowerShell module 'ImportRegistryHive' exists
if (Get-Module -ListAvailable -Name ImportRegistryHive) 
{
    # Create output directory
    Import-RegistryHive -File "$ROOT\Windows\System32\config\SYSTEM" -Key "HKLM\TEMP_SYSTEM" -Name SystemHive
    $CurrentControlSet = Get-ItemPropertyValue "SystemHive:\Select" -Name Current
    $ComputerName = Get-ItemPropertyValue "SystemHive:\ControlSet00$CurrentControlSet\Control\ComputerName\ComputerName" -Name ComputerName
    Remove-RegistryHive -Name SystemHive

    $OUTPUT = "$env:USERPROFILE\Desktop\MiniTimeline\$ComputerName"

    if (Test-Path $OUTPUT)
    {
        Get-ChildItem -Path "$OUTPUT" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
        New-Item "$OUTPUT" -ItemType Directory -Force | Out-Null
    }
    else
    {
        New-Item "$OUTPUT" -ItemType Directory -Force | Out-Null
    }
}
else
{
    Write-Host "[Error] PowerShell module 'ImportRegistryHive' NOT found." -ForegroundColor Red
    Exit
}

#############################################################################################################################################################################################

# Create a record of your Windows PowerShell session to a text file
Start-Transcript -Path "$OUTPUT\Transcript.txt"

# Get Start Time
$startTime = (Get-Date)

# Header
Write-Host "" ; Write-Host "Get-MiniTimeline v0.1 - Triage Collection and Timeline Generation w/ KAPE" ; Write-Host "(c) 2019 Martin Willing (https://evild3ad.com/)" ; Write-Host ""

# Analysis date (ISO 8601)
$DATE = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "Analysis date: $DATE UTC"
Write-Host ""

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Kroll Artifact Parser and Extractor (KAPE)

# Check for required .NET Framework 4.5 and later
if ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 394802)
{
    if (Test-Path "$KAPE")
    {
        # Mini Timeline Collection
        Write-Host "[Info]  Collecting Master File Table (`$MFT), Registry and Event Logs ... "
        New-Item "$OUTPUT\Mini_Timeline_Collection" -ItemType Directory -Force 2>&1 | Out-Null
        & $KAPE --tsource $ROOT --tdest "$OUTPUT\Mini_Timeline_Collection" --target MiniTimelineCollection --tdd False 2>&1 | Out-Null

        # Stats
        $Total = (Get-Content "$OUTPUT\Mini_Timeline_Collection\*_CopyLog.csv" | Measure-Object).Count -1
        $Size = "{0:N2} MB" -f ((Get-ChildItem –Force "$OUTPUT\Mini_Timeline_Collection" –Recurse -ErrorAction SilentlyContinue| Measure-Object Length -s).Sum / 1MB)
        if (($Total) -And ($Size)) { Write-Host "[Info]  $Total File(s) copied ($Size)" }

        # Module: Mini_Timeline (TLN format)
        Write-Host "[Info]  Creating Mini_Timeline w/ KAPE [approx. 2-6 min] ... "
        New-Item "$OUTPUT\Mini_Timeline" -ItemType Directory -Force 2>&1 | Out-Null

        # Module: Mini_Timeline_Slice_by_Daterange (TLN format)
        if (($dateRange) -And ($dateRange -like "*dateRange*"))
        {
        # Targeted Timeline Creation
        & $KAPE --msource "$OUTPUT\Mini_Timeline_Collection" --mdest "$OUTPUT\Mini_Timeline" --mflush --module Mini_Timeline,Mini_Timeline_Slice_by_Daterange --mvars "computerName:$ComputerName^$dateRange" 2>&1 | Out-Null
        }
        else
        {
        # Automated Timeline Creation
        & $KAPE --msource "$OUTPUT\Mini_Timeline_Collection" --mdest "$OUTPUT\Mini_Timeline" --mflush --module Mini_Timeline --mvars computerName:$ComputerName 2>&1 | Out-Null
        }

        Function Get-FileSize() {
        Param ([long]$Size)
        If ($Size -gt 1TB) {[string]::Format("{0:0.00} TB", $Size / 1TB)}
        ElseIf ($Size -gt 1GB) {[string]::Format("{0:0.00} GB", $Size / 1GB)}
        ElseIf ($Size -gt 1MB) {[string]::Format("{0:0.00} MB", $Size / 1MB)}
        ElseIf ($Size -gt 1KB) {[string]::Format("{0:0.00} KB", $Size / 1KB)}
        ElseIf ($Size -gt 0) {[string]::Format("{0:0.00} B", $Size)}
        Else {""}
        }

        # Full Timeline File Size (CSV)
        if (Test-Path "$OUTPUT\Mini_Timeline\Timeline\01_timeline.csv")
        {
        $File = "$OUTPUT\Mini_Timeline\Timeline\01_timeline.csv"
        $Size = Get-FileSize((Get-Item $File).Length)
        Write-Host "[Info]  Full Timeline File Size: $Size"
        }

        # Slice File Size (CSV)
        if (Test-Path "$OUTPUT\Mini_Timeline\Timeline\01_timeline_dateRange.csv")
        {
        $File = "$OUTPUT\Mini_Timeline\Timeline\01_timeline_dateRange.csv"
        $Size = Get-FileSize((Get-Item $File).Length)
        Write-Host "[Info]  Slice File Size: $Size"
        }

        # Stats
        $Total = (Get-ChildItem –Force "$OUTPUT\Mini_Timeline\Timeline" -Exclude "temp*" | Measure-Object).Count
        $Size = "{0:N2} MB" -f ((Get-ChildItem –Force "$OUTPUT\Mini_Timeline\Timeline" –Recurse -ErrorAction SilentlyContinue| Measure-Object Length -s).Sum / 1MB)
        if (($Total) -And ($Size)) { Write-Host "[Info]  $Total Timeline file(s) created ($Size)" }

        Write-Host "[Info]  Beautifying Timelines for Analysis ... "

        # Add Header Line (Timeline_Slice)
        $ImportFile = "$OUTPUT\Mini_Timeline\Timeline\Timeline_Slice.csv"
        $ImportFileNoHeader = "$OUTPUT\Mini_Timeline\Timeline\01_timeline_dateRange.csv"
        Clear-Content $ImportFile 2>&1 | Out-Null
        Add-Content $ImportFile “Time,Source,Host,User,Description”
        Get-Content $ImportFileNoHeader | Add-Content $ImportFile

        # Check if PowerShell module 'ImportExcel' exists
        if (Get-Module -ListAvailable -Name ImportExcel) 
        {
            # XLSX
            New-Item "$OUTPUT\Mini_Timeline\Timeline\XLSX" -ItemType Directory -Force | Out-Null
            $IMPORT = Import-Csv "$OUTPUT\Mini_Timeline\Timeline\Timeline_Slice.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT\Mini_Timeline\Timeline\XLSX\Timeline_Slice.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Timeline_Slice" -CellStyleSB {
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
            $EvtColor = [System.Drawing.Color]::FromArgb(217,217,217)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$B1="EVT"' -BackgroundColor $EvtColor
            # Source: ALERT --> Light Blue
            $AlertColor = [System.Drawing.Color]::FromArgb(0,176,240)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$B1="ALERT"' -BackgroundColor $AlertColor
            # Malicious: McAfee Quarantine Files (.bup) --> Red
            $MaliciousColor = [System.Drawing.Color]::FromArgb(255,0,0)
            Add-ConditionalFormatting -Address $WorkSheet.Dimension.Address -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND(".bup",$E1)))' -BackgroundColor $MaliciousColor
            }

            # Slice File Size (CSV)
            if (Test-Path "$OUTPUT\Mini_Timeline\Timeline\XLSX\Timeline_Slice.xlsx")
            {
            $File = "$OUTPUT\Mini_Timeline\Timeline\XLSX\Timeline_Slice.xlsx"
            $Size = Get-FileSize((Get-Item $File).Length)
            Write-Host "[Info]  Slice File Size (XLSX): $Size"
            }
        }
        else
        {
            Write-Host "[Error] PowerShell module 'ImportExcel' NOT found." -ForegroundColor Red
        }

        # Add Header Line (Timeline_dateRange)
        $ImportFile = "$OUTPUT\Mini_Timeline\Timeline\Timeline_dateRange.csv"
        $ImportFileNoHeader = "$OUTPUT\Mini_Timeline\Timeline\01_timeline_dateRange.csv"
        Clear-Content $ImportFile 2>&1 | Out-Null
        Add-Content $ImportFile “Time,Source,Host,User,Description”
        Get-Content $ImportFileNoHeader | Add-Content $ImportFile

        # Add Header Line (Timeline)
        $ImportFile = "$OUTPUT\Mini_Timeline\Timeline\Timeline.csv"
        $ImportFileNoHeader = "$OUTPUT\Mini_Timeline\Timeline\01_timeline.csv"
        Clear-Content $ImportFile 2>&1 | Out-Null
        Add-Content $ImportFile “Time,Source,Host,User,Description”
        Get-Content $ImportFileNoHeader | Add-Content $ImportFile
    }
    else
    {
    Write-Host "[Error] kape.exe NOT found." -ForegroundColor Red
    Exit
    }
}
else
{
Write-Host "[Error] KAPE requires Microsoft .NET Framework 4.5 or later." -ForegroundColor Red
Exit
}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Stop logging
Write-Host ""
Stop-Transcript

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Host ""
Write-Host "FINISHED!"
'Overall analysis duration: {0:hh} h {0:mm} min {0:ss} sec' -f ($endTime-$startTime)

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
# - FILE  --> Dark Green (0,176,80)  / Black Text
# - REG   --> Yellow (255,255,0)     / Black Text
# - ALERT --> Light Blue (0,176,240) / Black Text
# - EVT   --> Grey (217,217,217)     / Black Text
# - ???
#
# Bookmarks (Row):
# - Malicious  --> Red (255,0,0)      / Black Text
# - Suspicious --> Orange (255,192,0) / Black Text

#############################################################################################################################################################################################

# Links
# http://az4n6.blogspot.com/2019/08/triage-collection-and-timeline.html
# https://windowsir.blogspot.com/2009/02/timeline-analysis.html
# https://digital-forensics.sans.org/blog/2012/01/25/digital-forensic-sifting-colorized-super-timeline-template-for-log2timeline-output-files/