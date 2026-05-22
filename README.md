# SecurityTask v7 Full

Advanced Windows 11 Startup, Process, Persistence, and VirusTotal Security Auditor

---

## Overview

SecurityTask v7 Full is a graphical Windows security auditing application designed to help identify:

* Hidden persistence mechanisms
* Suspicious startup entries
* Malicious or impersonating processes
* Dangerous scheduled tasks
* WMI persistence
* Suspicious services
* Network connections
* Unsigned binaries
* Potential malware indicators
* VirusTotal detections

The application combines:

* Startup analysis
* Task Manager functionality
* Persistence hunting
* Network inspection
* Defender configuration auditing
* DLL/module analysis
* VirusTotal reputation scanning

into a single graphical Windows application.

---

# Features

## Startup & Persistence Scanner

Scans nearly all common Windows startup locations including:

### Registry Run Keys

* HKCU Run
* HKCU RunOnce
* HKLM Run
* HKLM RunOnce
* Policies Explorer Run
* Wow6432Node startup keys
* Winlogon Shell/Userinit
* AppInit DLLs
* IFEO Debugger persistence

### Startup Folders

* Current user startup folder
* All users startup folder

### Scheduled Tasks

Enumerates scheduled tasks and startup triggers.

### Services

Enumerates auto-start Windows services.

### WMI Persistence

Detects:

* CommandLineEventConsumer persistence
* WMI subscription abuse

---

# Process Scanner / Task Manager

Displays:

* Running processes
* Parent process IDs
* Command lines
* Executable paths
* Network connections
* Signatures
* SHA256 hashes
* VirusTotal results

Can detect:

* Hidden processes
* Processes visible in WMI but not normal enumeration
* LOLBins (Living-off-the-land binaries)
* Suspicious parent-child relationships
* Temp/AppData launched executables
* Encoded PowerShell attacks
* Fake Windows binaries

---

# Suspicious Behavior Detection

The application automatically highlights suspicious items.

## Color Coding

### Orange

Potentially suspicious:

* Unsigned binaries
* AppData execution
* Temp execution
* Encoded PowerShell
* LOLBins
* IFEO persistence
* WMI persistence

### Red

High-risk indicators:

* VirusTotal malicious detections
* Multiple suspicious indicators
* Fake Windows system binaries
* Known malware-like behavior

---

# VirusTotal Integration

Uses the official:

[vt-py GitHub Repository](https://github.com/VirusTotal/vt-py?utm_source=chatgpt.com)

## Features

* SHA256 hash lookups
* Live VT dashboard
* Rate limiting
* Queue management
* Cached results
* Live lookup history
* Statistics window
* Detection summaries

## Important

The application:

* DOES NOT upload files
* ONLY sends SHA256 hashes
* Uses public VirusTotal file reports

---

# VirusTotal Dashboard

Separate popup window showing:

* Current lookup
* Lookup queue
* Rate limit usage
* Previous results
* Clean vs malicious counts
* Cached lookups
* Errors
* Suspicious detections

---

# Network Scanner

Shows:

* Active TCP/UDP connections
* Local endpoints
* Remote endpoints
* Associated process IDs
* Suspicious ports

Flags:

* Common malware ports
* Reverse shell indicators
* IRC bot ports
* Suspicious outbound traffic

---

# Defender Exclusion Scanner

Enumerates Windows Defender exclusions including:

* Excluded paths
* Excluded processes
* Excluded extensions
* Excluded IPs

Useful for detecting:

* Malware persistence
* AV bypass attempts

---

# Module / DLL Scanner

Can inspect loaded modules for a selected process.

Displays:

* DLL paths
* Signature status
* Signers
* SHA256 hashes
* Suspicious locations

Useful for:

* DLL injection detection
* Unsigned module analysis
* Malware-loaded DLL hunting

---

# Additional Features

## CSV Export

Exports:

* Startup entries
* Processes
* Network connections
* Defender exclusions
* VirusTotal history

## Process Termination

Can terminate suspicious processes directly.

## File Location Access

Open executable locations in Explorer.

## Filtering

Real-time filtering/searching of all results.

---

# Requirements

## Operating System

* Windows 10
* Windows 11

## Python

* Python 3.10+

## Required Packages

Install dependencies:

```powershell
python -m pip install --upgrade psutil vt-py
```

---

# Running the Application

```powershell
python securitytask_v6_full.py
```

Recommended:

* Run PowerShell or Command Prompt as Administrator

---

# Security Notes

This tool is intended for:

* Malware analysis
* Incident response
* Threat hunting
* Security auditing
* Persistence investigation

This application:

* Does not exploit systems
* Does not bypass security
* Does not upload files automatically

VirusTotal integration only submits:

* SHA256 hashes

---

# Recommended Usage

## First Scan

1. Run as Administrator
2. Click "Full Scan"
3. Review orange/red entries
4. Investigate unsigned executables
5. Check VirusTotal detections

## VirusTotal Workflow

1. Set API key
2. Select suspicious process/startup item
3. Click:

   * "VT Lookup Selected"
     OR
   * "VT Lookup Suspicious 4"

## Investigation Workflow

1. Review suspicious indicators
2. Open executable location
3. Analyze signatures
4. Check VirusTotal reputation
5. Investigate network connections

---

# Known Limitations

* Some protected processes may restrict access
* Kernel-mode rootkits are not detectable from user mode
* Hidden drivers are not currently scanned
* ETW monitoring is not included
* Does not include memory forensics

---

# Future Expansion Ideas

Potential additions:

* YARA scanning
* Sigma rule support
* Autoruns comparison
* ETW monitoring
* Driver inspection
* Memory scanning
* Sysmon integration
* Windows event log analysis
* Persistence baselining
* Sandbox detonation support

---

# Disclaimer

Use responsibly.

This software is intended for:

* Defensive security
* Research
* Malware analysis
* System auditing

Always verify detections before removing files or terminating processes.
