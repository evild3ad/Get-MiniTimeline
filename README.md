# Get-MiniTimeline
Get-MiniTimeline.ps1 is a PowerShell script utilized to collect several forensic artifacts from a mounted forensic image and auto-generate a beautified MiniTimeline from the data collected.

Forensic Artifacts:  
* Master File Table ($MFT)  
* Windows Event Logs  
* Windows Registry  

## Download
Download the latest version of **Get-MiniTimeline** from the [releases](https://github.com/evild3ad/Get-MiniTimeline/releases) section.

## Usage
1. Mount your forensic image with e.g. drive letter `G:`  
Note: When your forensic image has multiple partitions you may have to change the path to the Windows partition.   

![Arsenal Image Mounter](https://github.com/evild3ad/Get-MiniTimeline/blob/master/Screenshots/AIM.png)
**Fig 1:** Arsenal Image Mounter (AIM) 

2. Enter your drive letter in `Get-MiniTimeline.ps1`  
`Input (Source)`  
`$ROOT = "G:"`  

3. Run Windows PowerShell console as Administrator.  

```
PS > .\Get-MiniTimeline.ps1 dateRange:MM/DD/YYYY-MM/DD/YYYY  
```

![PowerShell](https://github.com/evild3ad/Get-MiniTimeline/blob/master/Screenshots/PowerShell.png)
**Fig 2:** Running Get-MiniTimeline.ps1 (Example)

![Colorized Excel](https://github.com/evild3ad/Get-MiniTimeline/blob/master/Screenshots/Colorized-Excel.png)
**Fig 3:** Timeline_Slice.xlsx - The dateRange will be auto-beautified as colorized Excel sheet

![Timeline Explorer](https://github.com/evild3ad/Get-MiniTimeline/blob/master/Screenshots/TLE.png)
**Fig 4:** Timeline.csv - Full Timeline Analysis w/ Timeline Explorer (TLE)

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
https://www.evild3ad.com/3940/installing-importregistryhive-powershell-module/   

## Links
[SANS Webcast: Triage Collection and Timeline Generation with KAPE](https://www.youtube.com/watch?v=iYyWZSNBNcw)  
[SANS DFIR Blog: Triage Collection and Timeline Generation with KAPE](https://digital-forensics.sans.org/blog/2019/08/22/triage-collection-and-timeline-generation-with-kape)  