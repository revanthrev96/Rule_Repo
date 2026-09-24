// Process start events on Windows
#event_simpleName=ProcessRollup2 event_platform=Win

// 1. Browser is Edge or Chrome (any case)
| in(field="FileName", values=["msedge.exe","chrome.exe"], ignoreCase=true)

// 2. Remote debugging is enabled (port, pipe or address)
| CommandLine=/--remote-debugging-(port|pipe|address)/i

// 3. Launched by a script host or LOLBin (any case)
| ParentBaseFileName=/^(python|pythonw|powershell|pwsh|wscript|cscript|cmd|node|mshta|rundll32)\.exe$/i

// 4. Label: how the browser was hidden
| case {
    CommandLine=/--headless/i | Stealth:="headless" ;
    CommandLine=/--window-position=-\d{4,}|--start-minimized/i | Stealth:="hidden-window" ;
    * | Stealth:="visible" ;
  }

// 5. Label: which profile folder was used
| case {
    CommandLine=/--user-data-dir=.*\\Temp\\/i | Profile:="temp-dir" ;
    CommandLine=/--user-data-dir=/i | Profile:="custom" ;
    * | Profile:="default" ;
  }

// 6. Output for review during testing
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, Stealth, Profile, CommandLine])




*****************************************

```Writer runs from a user-writable folder and drops a .dll into the root of System32/SysWOW64 using an impersonation token. SysWOW64 covers 32-bit writes redirected from System32 by WOW64.```
ContextImageFileName IN ("*\\users\\*","*\\programdata\\*","*\\windows\\temp\\*","*\\perflogs\\*")
(system32 OR syswow64) ".dll"
TargetFileName IN ("*\\system32\\*.dll","*\\syswow64\\*.dll")
| regex TargetFileName="(?i)\\\\(system32|syswow64)\\\\[^\\\\]+\\.dll$"