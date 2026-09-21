# Perfkey Registry Hijack Resulting in Privileged DLL Execution

| Field | Value |
|---|---|
| Platform | CrowdStrike Falcon NG-SIEM (LogScale / CQL) |
| MITRE ATT&CK | T1574.011 Services Registry Permissions Weakness, T1112 Modify Registry |
| Severity | Critical (correlated), Medium (registry write only) |
| Status | Experimental, validate field names in your tenant before production |

## Description

An attacker who can write to a service's registry key adds a `Performance` subkey whose `Library` value points to a malicious DLL. When performance counters are queried, for example through WMI `Win32_Perf*` classes, Perflib loads the DLL inside a privileged process, usually `WmiPrvSE.exe` running as SYSTEM.

This rule correlates two stages on the same host:

1. A write to `HKLM\SYSTEM\*\Services\<svc>\Performance\Library`
2. An unsigned, non-System32 module load of the same DLL name within 1 hour, after the write

## Correlated rule (critical)

```
#event_simpleName=/^(RegGenericValueUpdate|AsepValueUpdate|RegSystemConfigValueUpdate|UnsignedModuleLoad)$/
| case {
    #event_simpleName=/^Reg/
      RegObjectName=/\\Services\\[^\\]+\\Performance$/i
      RegValueName=/^Library$/i
      | Stage := "reg_write"
      | DllPath := RegStringValue
      | RegTime := @timestamp ;
    #event_simpleName=UnsignedModuleLoad
      ImageFileName!=/\\Windows\\(System32|SysWOW64)\\/i
      | Stage := "dll_load"
      | DllPath := ImageFileName
      | LoadTime := @timestamp ;
  }
| regex("(?<DllName>[^\\\\/]+\.dll)$", field=DllPath, strict=true)
| DllName := lower(DllName)
| groupBy([aid, ComputerName, DllName], function=[
    count(Stage, distinct=true, as=Stages),
    min(RegTime, as=FirstWrite),
    max(LoadTime, as=LastLoad),
    collect([RegObjectName, RegStringValue, DllPath, ContextProcessId, SHA256HashData])
  ])
| Stages=2
| test(LastLoad > FirstWrite)
| test(LastLoad - FirstWrite <= 3600000)
| Service := replace(regex="(?i).*\\\\Services\\\\([^\\\\]+)\\\\Performance.*", with="$1", field=RegObjectName)
| table([ComputerName, Service, DllName, DllPath, RegStringValue, FirstWrite, LastLoad, SHA256HashData])
```

## Standalone registry-write rule (medium)

Keep this alongside the correlated rule so a planted DLL is caught before anything triggers it.

```
#event_simpleName=/^(RegGenericValueUpdate|AsepValueUpdate|RegSystemConfigValueUpdate)$/
| RegObjectName=/\\Services\\[^\\]+\\Performance$/i
| RegValueName=/^(Library|Open|Collect|Close)$/i
| join(query={#event_simpleName=ProcessRollup2},
       field=[aid, ContextProcessId], key=[aid, TargetProcessId],
       include=[ImageFileName, CommandLine, UserName])
| ImageFileName!=/\\(TrustedInstaller|TiWorker|msiexec|lodctr|unlodctr)\.exe$/i
| regex("\\\\Services\\\\(?<Service>[^\\\\]+)\\\\Performance", field=RegObjectName)
| SuspiciousPath := if(RegStringValue=/\\(Users|ProgramData|Temp|AppData|Public)\\|^\\\\/i, then="yes", else="no")
| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine,
         Service, RegValueName, RegStringValue, SuspiciousPath])
```

## Deployment

- Schedule: every 15 minutes
- Lookback: 75 to 90 minutes, so a write and load that straddle two runs are still correlated
- Correlation window: 1 hour (`3600000` ms), adjust as needed

## False positives

- Product installers registering performance counters. Allowlist by signer or hash, not process name.
- Run the standalone rule over 30 days to baseline before enabling alerting.

## Known gaps

- Signed malicious DLLs do not generate `UnsignedModuleLoad`. Add `ClassifiedModuleLoad` to the second branch if available.
- The correlated rule does not filter on the loading process. Join `ProcessRollup2` on `aid` + `ContextProcessId` after `groupBy` to enrich with the loader name.
- `Library` values may use `%SystemRoot%` or a bare file name, which is why correlation uses the DLL file name rather than the full path.

## References

- MITRE ATT&CK T1574.011: https://attack.mitre.org/techniques/T1574/011/
- itm4n, "Windows RpcEptMapper Service Insecure Registry Permissions EoP"
