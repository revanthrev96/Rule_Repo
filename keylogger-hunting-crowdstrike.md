# Hunting Keyloggers with CrowdStrike Falcon (Windows & Linux)

A practical guide to how keyloggers work, what telemetry EDRs rely on to spot them, and CrowdStrike Query Language (CQL / LogScale) hunts for Windows and Linux.

> **Note:** CrowdStrike does not publicly document its exact event names for API-level keylogging telemetry. They are listed in the **Events Data Dictionary** inside the Falcon console and vary by sensor version and OS. Always start with the discovery queries below to confirm what your tenant collects.

---

## Table of Contents

1. [Windows: How Keyloggers Work](#1-windows-how-keyloggers-work)
2. [Windows: How EDRs See It](#2-windows-how-edrs-see-it)
3. [Windows: Hunting Queries](#3-windows-hunting-queries)
4. [Linux: How Keyloggers Work](#4-linux-how-keyloggers-work)
5. [Linux: Hunting Queries](#5-linux-hunting-queries)
6. [Linux: Visibility Gaps](#6-linux-visibility-gaps)
7. [Why a Custom Keylogger May Not Trigger an Alert](#7-why-a-custom-keylogger-may-not-trigger-an-alert)
8. [Validating What Falcon Recorded](#8-validating-what-falcon-recorded)
9. [Closing the Detection Gap](#9-closing-the-detection-gap)
10. [Screen Capture (T1113)](#10-screen-capture-t1113)
11. [Staging & Exfiltration of Captured Data](#11-staging--exfiltration-of-captured-data)
12. [References](#12-references)

---

## 1. Windows: How Keyloggers Work

Almost all Windows keyloggers use one of four techniques:

| Technique | API(s) | What to look for |
|---|---|---|
| **Polling** | `GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState` | Tight-loop calls from a background (non-foreground) process |
| **Hooking** | `SetWindowsHookEx` | Hook type `WH_KEYBOARD_LL` (13) or `WH_KEYBOARD` (2) |
| **Raw Input** | `RegisterRawInputDevices`, `GetRawInputData` | `RIDEV_INPUTSINK` flag — receives keystrokes even when not focused |
| **DirectInput** | DirectX keyboard APIs | Non-game processes using DirectInput keyboard devices |

MITRE ATT&CK: **T1056.001 – Input Capture: Keylogging**

---

## 2. Windows: How EDRs See It

Modern EDRs observe these calls via the **Microsoft-Windows-Win32k ETW provider**. Public research (Asuka Nakajima, NULLCON 2025; Elastic Security Labs) uses these events:

| ETW Event ID | API | Suspicious condition |
|---|---|---|
| 1001 | `RegisterRawInputDevices` | `Flags = RIDEV_INPUTSINK` |
| 1002 | `SetWindowsHookEx` | `FilterType = WH_KEYBOARD_LL` |
| 1003 | `GetAsyncKeyState` | `MsSinceLastKeyEvent > 100` and `BackgroundCallCount > 400` |

Falcon's equivalent events (if present in your tenant) have their own names — use Query 3.1 to discover them.

---

## 3. Windows: Hunting Queries

### 3.1 Discover keylogger-related event types in your tenant

```
#event_simpleName=/Hook|KeyState|RawInput|Keyboard|Keylog/i
| groupBy([#event_simpleName], limit=1000)
```

### 3.2 Existing detections mapped to Input Capture (T1056)

```
"T1056" OR "Input Capture" OR "Keylog"
| groupBy([ComputerName, #event_simpleName], limit=1000)
```

### 3.3 Script-based keyloggers (PowerShell / Add-Type calling user32.dll)

```
#event_simpleName=/ProcessRollup2|CommandHistory|ScriptControlScanTelemetry/
| /GetAsyncKeyState|SetWindowsHookEx|GetKeyboardState|RegisterRawInputDevices|WH_KEYBOARD_LL|Get-Keystrokes/i
| table([@timestamp, ComputerName, UserName, #event_simpleName, FileName, CommandLine])
```

### 3.4 Rare processes running from user-writable paths (droppers / custom tools)

```
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(AppData|Temp|ProgramData|Public)\\/i
| groupBy([FileName, SHA256HashData], function=[count(aid, distinct=true, as=Hosts)])
| Hosts < 3
```

Pivot on rare hashes: check their `NetworkConnectIP4` and `DnsRequest` activity for exfiltration.

### Tuning tips

- Allowlist legitimate callers: AutoHotkey, accessibility tools, remote-desktop agents, games, hotkey utilities, IMEs.
- Prioritise processes that are **unsigned**, **run from user-writable paths**, **run in the background**, and **make outbound connections**.

---

## 4. Linux: How Keyloggers Work

| Technique | Mechanism | Notes |
|---|---|---|
| **Raw input devices** | Reading `/dev/input/event*` | logkeys and most custom tools; needs root or `input` group |
| **X11 snooping** | `xinput test`, `XQueryKeymap`, XRecord extension | Any X client can read other windows' keys (xspy, xkeylogger) |
| **TTY / SSH sniffing** | `strace` / `ptrace` attached to `sshd`, `bash`, `sudo` | Captures typed passwords |
| **PAM abuse** | Malicious PAM module or enabling `pam_tty_audit` | Logs keystrokes / credentials |
| **LD_PRELOAD** | Hooking `read()` in shells or ssh | Via `LD_PRELOAD=` or `/etc/ld.so.preload` |
| **Kernel / eBPF** | Rootkit using `register_keyboard_notifier`, or eBPF probes on `tty_write` / `tty_read` | Hardest to see from userland |

---

## 5. Linux: Hunting Queries

### 5.1 Discover Linux event types in your tenant

```
event_platform=Lin
| groupBy([#event_simpleName], limit=1000)
```

### 5.2 Known keylogger tools and input-device access

```
#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/\/dev\/input\/|xinput\s+test|logkeys|xspy|xkeylogger|showkey|evtest|\/dev\/uinput/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName])
```

### 5.3 ptrace / strace on sshd, shells or sudo (credential sniffing)

```
#event_simpleName=ProcessRollup2 event_platform=Lin
| FileName=/^(strace|ltrace|gdb)$/
| CommandLine=/-p\s*\d+|sshd|bash|sudo|passwd/i
| table([@timestamp, ComputerName, UserName, CommandLine, ParentBaseFileName])
```

### 5.4 PAM, LD_PRELOAD and TTY-audit tampering

```
#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/\/etc\/pam\.d|pam_tty_audit|ld\.so\.preload|LD_PRELOAD=|\/lib\/security\/.*\.so/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
```

### 5.5 Kernel module loads (possible rootkit keyboard notifiers)

```
#event_simpleName=ProcessRollup2 event_platform=Lin
| FileName=/^(insmod|modprobe|kmod)$/
| table([@timestamp, ComputerName, UserName, CommandLine])
```

---

## 6. Linux: Visibility Gaps

Falcon on Linux generally does **not** log every file open, so a compiled binary silently reading `/dev/input` may not appear in the queries above. Supplement with:

- **auditd** rules, for example:
  ```
  -w /dev/input -p r -k input_read
  -a always,exit -F arch=b64 -S ptrace -k ptrace_use
  -a always,exit -F arch=b64 -S bpf -k bpf_use
  ```
- **File Integrity Monitoring** (e.g. Falcon FileVantage) on `/etc/ld.so.preload`, `/etc/pam.d/`, and `/lib/security/`.

---

## 7. Why a Custom Keylogger May Not Trigger an Alert

Falcon separates two things:

- **Telemetry** — process start, network connections, DNS, file writes and some API-level events are recorded for almost every process, custom or not.
- **Detections / preventions** — an alert fires only when behaviour crosses CrowdStrike's thresholds or your prevention policy.

A custom keylogger that polls `GetAsyncKeyState` or installs a low-level hook, with no known hash and no malicious parent chain, often **won't raise a detection**. Many legitimate apps make the same calls, so these signals are tuned conservatively. This is expected behaviour for any EDR, not a Falcon bug.

"CrowdStrike isn't capturing it" usually means **no alert**, not **no data**.

---

## 8. Validating What Falcon Recorded

Run the tool on a test host, then:

**Step 1 — find the process**

```
#event_simpleName=ProcessRollup2 ComputerName="TEST-HOST" FileName="their_tool.exe"
| table([@timestamp, aid, TargetProcessId, SHA256HashData, CommandLine, ParentBaseFileName])
```

**Step 2 — list every event Falcon recorded for that process**

```
aid="<aid>" (ContextProcessId="<pid>" OR TargetProcessId="<pid>")
| groupBy([#event_simpleName], limit=1000)
```

- **Hook / keystate / raw-input events present** → telemetry exists; build hunts on it.
- **Only process / network / file events** → Falcon isn't exposing API calls for that technique on that sensor/OS; hunt on surrounding behaviour instead.

---

## 9. Closing the Detection Gap

- **Prevention policy** — for a test group, set cloud and sensor ML to aggressive / extra-aggressive and enable suspicious-process and behavioural protections. Default policies are often looser.
- **Exclusions** — confirm the test host and the developer's build folders are **not** covered by ML or IOA exclusions. Dev machines often are, which alone explains a silent result.
- **Sensor group** — make sure the test host is in the intended host/sensor group.
- **Custom IOAs** — these trigger on process creation, file creation, network connections and domains (not API calls). Target what a keylogger must do:
  - execute from user-writable paths
  - write a log file
  - persist via Run keys or scheduled tasks
  - send data out
- **Scheduled searches** — if API-level telemetry exists, turn the hunts into scheduled searches that alert on rare processes making those calls.
- **Report the false negative** — submit the sample to CrowdStrike Support or Falcon Sandbox so detection logic can be improved.

---

## 10. Screen Capture (T1113)

Modern keyloggers and infostealers (e.g. Agent Tesla, Snake, Remcos-style RATs) combine keystroke logging with periodic screenshots. The keylogging queries above will **not** catch screen capture — it uses different APIs.

### What screenshot tools use

| OS | Mechanism |
|---|---|
| **Windows** | `GetDC` / `GetWindowDC` + `BitBlt`, `PrintWindow`, .NET `Graphics.CopyFromScreen` (common in PowerShell stealers), DXGI Desktop Duplication, `Windows.Graphics.Capture` |
| **Linux** | `import` (ImageMagick), `xwd`, `scrot`, `gnome-screenshot`, `ffmpeg -f x11grab`, `grim` (Wayland) |

### 10.1 Discover screen-capture / image-write event types in your tenant

```
#event_simpleName=/Screen|Capture|BitBlt|Jpeg|Png|Bmp|Image/i
| groupBy([#event_simpleName], limit=1000)
```

### 10.2 PowerShell / script-based screenshot code (Windows)

```
#event_simpleName=/ProcessRollup2|CommandHistory|ScriptControlScanTelemetry/
| /CopyFromScreen|BitBlt|PrintWindow|GetWindowDC|PrimaryScreen\.Bounds|System\.Drawing\.Bitmap|Graphics\.Capture/i
| table([@timestamp, ComputerName, UserName, #event_simpleName, FileName, CommandLine])
```

### 10.3 Linux screenshot tools

```
#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/\bimport\s+-window|xwd\b|scrot|gnome-screenshot|x11grab|\bgrim\b/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName])
```

### 10.4 Repeated image writes from unusual processes

Compiled custom tools won't expose API calls in a command line, so hunt on what they leave behind: a non-browser, non-imaging process writing `.png` / `.jpg` / `.bmp` files repeatedly to Temp / AppData / ProgramData.

Replace `<ImageWriteEvent>` with the event name(s) found in 10.1:

```
#event_simpleName=<ImageWriteEvent> event_platform=Win
| TargetFileName=/\\(AppData|Temp|ProgramData|Public)\\.*\.(png|jpe?g|bmp)$/i
| groupBy([aid, ComputerName, ContextProcessId], function=[count(as=ImageWrites), min(@timestamp, as=First), max(@timestamp, as=Last)])
| ImageWrites > 10
| sort(ImageWrites, order=desc)
```

Pivot each hit back to its process with the Step 2 query in [Section 8](#8-validating-what-falcon-recorded).

---

## 11. Staging & Exfiltration of Captured Data

Whatever technique a keylogger uses, captured data must be **stored** and/or **sent out**. These steps are hard to avoid, which makes them the most reliable hunting point for custom tools.

### 11.1 Archive creation (staging keystroke logs / screenshots)

```
#event_simpleName=ProcessRollup2
| CommandLine=/Compress-Archive|7z(a|\.exe)?\s+a\s|rar(\.exe)?\s+a\s|tar\s+-?c|zip\s+-r|makecab/i
| CommandLine=/AppData|Temp|ProgramData|Public|\/tmp\/|\/dev\/shm/i
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName])
```

### 11.2 Connections to common stealer exfil channels (non-browser processes)

Telegram bot API, Discord webhooks, paste / file-sharing sites and tunnels are heavily used by commodity stealers.

```
#event_simpleName=DnsRequest
| DomainName=/api\.telegram\.org|discord(app)?\.com|webhook|pastebin\.com|transfer\.sh|file\.io|gofile\.io|anonfiles|ngrok|trycloudflare\.com/i
| join({#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, ImageFileName, CommandLine])
| FileName!=/^(chrome|msedge|firefox|brave|opera|iexplore|discord|telegram|slack|teams)\.exe$/i
| table([@timestamp, ComputerName, FileName, ImageFileName, DomainName, CommandLine])
```

### 11.3 SMTP / FTP exfil from processes that aren't mail or FTP clients

Many keyloggers (e.g. Agent Tesla, Snake) email or FTP their logs.

```
#event_simpleName=NetworkConnectIP4
| in(field=RemotePort, values=["21", "25", "465", "587"])
| join({#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], key=[aid, TargetProcessId], include=[FileName, ImageFileName])
| FileName!=/^(outlook|thunderbird|filezilla|winscp|olk)\.exe$/i
| groupBy([FileName, ImageFileName, RemoteAddressIP4, RemotePort], function=[count(aid, distinct=true, as=Hosts)])
| sort(Hosts, order=asc)
```

### 11.4 Putting it together: the full behavioural chain

A high-confidence keylogger/stealer pattern on a single host:

1. Rare or unsigned process runs from a user-writable path (Query 3.4)
2. It makes keyboard-capture calls (Queries 3.1 / 3.3) **and/or** writes images repeatedly (Query 10.4)
3. Files are archived (Query 11.1)
4. The same process connects to an exfil channel (Queries 11.2 / 11.3)

Any **two** of these on the same `aid` + process within a short window deserves investigation.

> **Field names:** `RemotePort`, `RemoteAddressIP4`, `TargetFileName` and `ContextProcessId` are standard Falcon fields, but some Next-Gen SIEM views also normalise them (e.g. `RPort`, `RemoteIP`). Adjust to match what your tenant shows.

---

## 12. References

- [Velociraptor – Windows.Detection.Keylogger](https://docs.velociraptor.app/exchange/artifacts/pages/windows.detection.keylogger)
- [Elastic Security Labs – Protecting your devices from information theft: Keylogger protection](https://www.elastic.co/security-labs/protecting-your-devices-from-information-theft-keylogger-protection)
- [MITRE ATT&CK T1056.001 – Input Capture: Keylogging](https://attack.mitre.org/techniques/T1056/001/)
- [MITRE ATT&CK T1113 – Screen Capture](https://attack.mitre.org/techniques/T1113/)
- [MITRE ATT&CK T1560 – Archive Collected Data](https://attack.mitre.org/techniques/T1560/)
- [MITRE ATT&CK T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- CrowdStrike Falcon Events Data Dictionary (Falcon console → Support and resources)
