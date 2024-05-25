<img src="https://img.shields.io/badge/Language-Powershell-blue"> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen"> [![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/evild3ad/Get-MiniTimeline?include_prereleases&style=flat&label=Release)](https://github.com/evild3ad/Get-MiniTimeline/releases) [![GitHub](https://img.shields.io/github/license/evild3ad/Get-MiniTimeline?style=flat&label=License)](LICENSE) <a href="https://www.linkedin.com/in/martin-willing-86343565/"><img src="https://img.shields.io/badge/LinkedIn-evild3ad-0077B5.svg?logo=LinkedIn"></a> <a href="https://twitter.com/Evild3ad79"><img src="https://img.shields.io/twitter/follow/Evild3ad79?style=social"></a>

# Get-MiniTimeline
Get-MiniTimeline.ps1 is a PowerShell script utilized to collect several forensic artifacts from a mounted forensic disk image and auto-generate a beautified MiniTimeline from the data collected.

Forensic Artifacts:  
* Master File Table ($MFT)  
* Windows Event Logs  
* Windows Registry  

## Download
Download the latest version of **Get-MiniTimeline** from the [Releases](https://github.com/evild3ad/Get-MiniTimeline/releases) section.

## Usage
1. Mount your forensic disk image with e.g. drive letter `G:`  
Note: When your forensic disk image has multiple partitions you may have to change the path to the Windows partition.   

![Arsenal Image Mounter](https://github.com/evild3ad/Get-MiniTimeline/blob/9ea8d83e20d685dd14ebe3b6f646f0980579c223/Screenshots/01.png)
**Fig 1:** Arsenal Image Mounter (AIM) 

2. Enter your drive letter in `Get-MiniTimeline.ps1`  
`Input (Source)`  
`$ROOT = "G:"`   

Optional: You can also change the outpath path.  
`$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\MiniTimeline\$ComputerName"`

3. Run Windows PowerShell console as Administrator.  

```
PS > .\Get-MiniTimeline.ps1 dateRange:MM/DD/YYYY-MM/DD/YYYY  
```

![PowerShell](https://github.com/evild3ad/Get-MiniTimeline/blob/9ea8d83e20d685dd14ebe3b6f646f0980579c223/Screenshots/02.png)  
**Fig 2:** Running Get-MiniTimeline.ps1 (Example)  

![MessageBox](https://github.com/evild3ad/Get-MiniTimeline/blob/9ea8d83e20d685dd14ebe3b6f646f0980579c223/Screenshots/03.png)  
**Fig 3:** Message Box  

![Colorized Excel](https://github.com/evild3ad/Get-MiniTimeline/blob/9ea8d83e20d685dd14ebe3b6f646f0980579c223/Screenshots/04.png)  
**Fig 4:** Timeline_Slice.xlsx - The dateRange will be auto-beautified as colorized Excel sheet  

![Timeline Explorer](https://github.com/evild3ad/Get-MiniTimeline/blob/9ea8d83e20d685dd14ebe3b6f646f0980579c223/Screenshots/05.png)  
**Fig 5:** Timeline.csv - Full Timeline Analysis w/ Timeline Explorer (TLE)  

## Dependencies
KAPE v1.3.0.2 (2023-01-03)  
https://ericzimmerman.github.io/  
https://binaryforay.blogspot.com/search?q=KAPE  
https://ericzimmerman.github.io/KapeDocs/  
https://www.kroll.com/kape  

EvtxECmd v1.5.0.0 (.NET 6)  
https://ericzimmerman.github.io/  

MFTECmd v1.2.2.0 (.NET 6)  
https://ericzimmerman.github.io/    

RegRipper v3.0 (2020-05-28)     
https://github.com/keydet89/RegRipper3.0  

TLN Tools   
https://github.com/mdegrazia/KAPE_Tools   
https://github.com/keydet89/Tools/tree/master/exe   

ImportExcel v7.8.9 (2024-05-18)     
https://github.com/dfinke/ImportExcel  
  

## Links
[SANS Webcast: Triage Collection and Timeline Generation with KAPE](https://www.youtube.com/watch?v=iYyWZSNBNcw)  
[SANS DFIR Blog: Triage Collection and Timeline Generation with KAPE](https://digital-forensics.sans.org/blog/2019/08/22/triage-collection-and-timeline-generation-with-kape)  
[Kroll - Express Artifact Analysis and Timeline Development with KAPE (YouTube)](https://www.youtube.com/watch?v=O5VW0Yr7guQ)  
[Kroll - Express Artifact Analysis and Timeline Development with KAPE (Slides)](https://www.kroll.com/-/media/kroll/pdfs/webinars/artifact-analysis-timelining-with-kape.pdf)