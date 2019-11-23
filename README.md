# Get-MiniTimeline
Triage Collection and Timeline Generation w/ KAPE

## Description
Get-MiniTimeline.ps1 is a PowerShell script utilized to collect several forensic artifacts from a mounted forensic image and to auto-generate a MiniTimeline.

Forensic Artifacts:
    - Master File Table ($MFT)
    - Windows Event Logs
    - Windows Registry

## Dependencies
KAPE v0.8.8.0 (2019-10-23)
https://ericzimmerman.github.io/
https://binaryforay.blogspot.com/search?q=KAPE

EvtxECmd v0.5.2.0 (2019-08-26)
https://ericzimmerman.github.io/

MFTECmd v0.4.4.6 (2019-08-30)
https://ericzimmerman.github.io/

RegRipper v2.8 (2019-08-14)
https://github.com/keydet89/RegRipper2.8

TLN Tools
https://github.com/mdegrazia/KAPE_Tools
https://github.com/keydet89/Tools/tree/master/exe

ImportExcel 6.5.2
https://github.com/dfinke/ImportExcel

ImportRegistryHive.psm1 by Chris Redit
https://blog.redit.name/posts/2015/powershell-loading-registry-hive-from-file.html

## Usage
1. Mount your forensic image with e.g. drive letter X: (\\.X:)
   Note: When your forensic image has multiple partitions you may have to change the path to the Windows partition.

![Arsenal Image Mounter](https://github.com/evild3ad/Get-MiniTimeline/blop/master/Screenshots/AIM.png)

2. Enter your drive letter 'Input (Source)' in 'Get-MiniTimeline.ps1'
   $ROOT = "X:"

3. Run Windows PowerShell as Administrator.

```
PS > .\Get-MiniTimeline.ps1 dateRange:MM/DD/YYYY-MM/DD/YYYY
```

![PowerShell](https://github.com/evild3ad/Get-MiniTimeline/blop/master/Screenshots/PowerShell.png)

![PowerShell](https://github.com/evild3ad/Get-MiniTimeline/blop/master/Screenshots/Colorized-Excel.png)

![PowerShell](https://github.com/evild3ad/Get-MiniTimeline/blop/master/Screenshots/TLE.png)

## Links
https://www.youtube.com/watch?v=iYyWZSNBNcw
https://digital-forensics.sans.org/blog/2019/08/22/triage-collection-and-timeline-generation-with-kape