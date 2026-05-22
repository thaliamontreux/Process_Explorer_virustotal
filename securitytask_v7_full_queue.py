
"""
SecurityTask v6 Full
--------------------
Windows 11 graphical startup, process, network, Defender, module, signature,
hash, and VirusTotal auditing tool.

Run:
  python securitytask_v6_full.py

Install:
  python -m pip install --upgrade psutil vt-py

Recommended:
  Run Command Prompt or PowerShell as Administrator.

VirusTotal:
  - Uses official vt-py if installed.
  - Set your key with the GUI button.
  - Only submits SHA256 hashes, not files.
  - Local rate limit: 4 lookups per minute.
"""

from __future__ import annotations

import csv
import ctypes
import datetime as dt
import hashlib
import json
import os
import queue
import re
import shlex
import subprocess
import threading
import time
import tkinter as tk
from dataclasses import asdict, dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import winreg  # type: ignore
except ImportError:
    winreg = None

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None

try:
    import vt  # type: ignore
except ImportError:
    vt = None


APP_TITLE = "SecurityTask v7 Full Queue - Windows Security Auditor"
APP_VERSION = "7.0-full-queue"

ORANGE = "#ffb347"
RED = "#ff6b6b"
GREEN = "#c8f7c5"

SUSPICIOUS_DIR_PARTS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\temp\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\windows\\tasks\\",
    "\\$recycle.bin\\",
    "\\recycler\\",
]

SUSPICIOUS_NAME_PATTERNS = [
    r"^[a-f0-9]{8,}\.exe$",
    r"^[a-z]{1,2}\d{4,}\.exe$",
    r"^(svch0st|scvhost|expl0rer|lsasss|csrsss|winlog0n|rundl132)\.exe$",
]

WINDOWS_SYSTEM_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "spoolsv.exe", "taskhostw.exe", "runtimebroker.exe", "sihost.exe",
    "fontdrvhost.exe", "audiodg.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "securityhealthservice.exe",
}

GOOD_WINDOWS_PATH_PREFIXES = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
]

LIVING_OFF_THE_LAND = {
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "cmd.exe",
}


@dataclass
class StartupItem:
    severity: str
    category: str
    name: str
    path: str
    command: str
    source: str
    signer: str
    signature_status: str
    sha256: str
    virustotal: str
    suspicious: str


@dataclass
class ProcessItem:
    severity: str
    pid: int
    ppid: int
    name: str
    exe: str
    username: str
    status: str
    created: str
    signer: str
    signature_status: str
    sha256: str
    virustotal: str
    connections: str
    suspicious: str
    cmdline: str


@dataclass
class NetworkItem:
    severity: str
    pid: int
    process: str
    local: str
    remote: str
    status: str
    suspicious: str


@dataclass
class DefenderExclusion:
    severity: str
    kind: str
    value: str
    suspicious: str


_sig_cache: Dict[str, Tuple[str, str]] = {}
_hash_cache: Dict[str, str] = {}
_vt_cache: Dict[str, str] = {}
_vt_lock = threading.Lock()
_vt_request_times: List[float] = []
_vt_api_key = ""


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_cmd(command: List[str], timeout: int = 60) -> str:
    try:
        creationflags = subprocess.CREATE_NO_WINDOW if is_windows() else 0
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=creationflags,
        )
        return completed.stdout.strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def powershell_json(script: str, timeout: int = 90):
    out = run_cmd(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout,
    )
    if not out or out.startswith("ERROR:"):
        return []
    try:
        data = json.loads(out)
        if data is None:
            return []
        if isinstance(data, dict):
            return [data]
        return data
    except json.JSONDecodeError:
        return []


def normalize_path(value: str) -> str:
    value = (value or "").strip().strip('"').strip("'")
    if not value:
        return ""
    return os.path.expandvars(value).strip().strip('"').strip("'")


def extract_executable(command: str) -> str:
    if not command:
        return ""
    expanded = os.path.expandvars(str(command)).strip()

    quoted = re.match(r'^"([^"]+\.(?:exe|dll|bat|cmd|ps1|vbs|js|msi))"', expanded, re.I)
    if quoted:
        return normalize_path(quoted.group(1))

    drive_path = re.search(r"([A-Z]:\\[^\r\n\t]+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|msi))", expanded, re.I)
    if drive_path:
        candidate = drive_path.group(1).strip()
        for ext in [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"]:
            idx = candidate.lower().find(ext)
            if idx >= 0:
                return normalize_path(candidate[:idx + len(ext)])

    try:
        parts = shlex.split(expanded, posix=False)
        if parts:
            first = parts[0].strip('"')
            return normalize_path(first)
    except Exception:
        pass

    return ""


def file_sha256(path: str) -> str:
    path = normalize_path(path)
    if not path or not os.path.isfile(path):
        return ""
    key = path.lower()
    if key in _hash_cache:
        return _hash_cache[key]
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        digest = h.hexdigest()
        _hash_cache[key] = digest
        return digest
    except Exception:
        return ""


def authenticode_signature(path: str) -> Tuple[str, str]:
    path = normalize_path(path)
    if not is_windows() or not path or not os.path.exists(path):
        return "", "Unavailable"
    key = path.lower()
    if key in _sig_cache:
        return _sig_cache[key]
    safe = path.replace("'", "''")
    script = f"""
    $s = Get-AuthenticodeSignature -FilePath '{safe}' -ErrorAction SilentlyContinue
    if ($null -eq $s) {{
      [pscustomobject]@{{Signer=''; Status='Unavailable'}}
    }} else {{
      $name = ''
      if ($s.SignerCertificate) {{ $name = $s.SignerCertificate.Subject }}
      [pscustomobject]@{{Signer=$name; Status=$s.Status.ToString()}}
    }} | ConvertTo-Json -Depth 3
    """
    data = powershell_json(script, timeout=45)
    if data:
        signer = str(data[0].get("Signer") or "")
        status = str(data[0].get("Status") or "Unavailable")
    else:
        signer, status = "", "Unavailable"
    _sig_cache[key] = (signer, status)
    return signer, status


def set_virustotal_api_key(key: str) -> None:
    global _vt_api_key
    _vt_api_key = (key or "").strip()


def get_virustotal_api_key() -> str:
    return _vt_api_key or os.environ.get("VIRUSTOTAL_API_KEY", "").strip()


def _clean_vt_window(max_per_minute: int = 4) -> None:
    now = time.time()
    while _vt_request_times and now - _vt_request_times[0] >= 65:
        _vt_request_times.pop(0)


def vt_rate_state(max_per_minute: int = 4) -> Tuple[int, int, int]:
    with _vt_lock:
        _clean_vt_window(max_per_minute)
        used = len(_vt_request_times)
        remaining = max(0, max_per_minute - used)
        reset = 0
        if _vt_request_times:
            reset = max(0, int(65 - (time.time() - _vt_request_times[0])))
        return used, remaining, reset


def wait_for_vt_slot(event_cb=None, sha256: str = "", source: str = "") -> None:
    while True:
        with _vt_lock:
            _clean_vt_window(4)
            now = time.time()
            if len(_vt_request_times) < 4:
                _vt_request_times.append(now)
                used, remaining, reset = vt_rate_state_unlocked()
                if event_cb:
                    event_cb("Sending", sha256, f"Sending to VirusTotal. Used={used}/4, remaining={remaining}, reset={reset}s", source, False)
                return
            wait_seconds = max(1, int(65 - (now - _vt_request_times[0]) + 1))
        if event_cb:
            event_cb("Waiting", sha256, f"Rate limit reached. Waiting {wait_seconds}s before sending.", source, False)
        time.sleep(min(wait_seconds, 5))


def vt_rate_state_unlocked(max_per_minute: int = 4) -> Tuple[int, int, int]:
    _clean_vt_window(max_per_minute)
    used = len(_vt_request_times)
    remaining = max(0, max_per_minute - used)
    reset = 0
    if _vt_request_times:
        reset = max(0, int(65 - (time.time() - _vt_request_times[0])))
    return used, remaining, reset


def parse_vt_response(response: dict) -> str:
    attrs = response.get("data", {}).get("attributes", {}) if isinstance(response, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    timeout = int(stats.get("timeout", 0) or 0)
    failure = int(stats.get("failure", 0) or 0)
    reputation = attrs.get("reputation", "")
    meaningful = attrs.get("meaningful_name", "") or ""
    names = attrs.get("names", []) or []
    threat = attrs.get("popular_threat_classification", {}) or {}
    threat_label = threat.get("suggested_threat_label", "") or ""

    parts = [
        f"malicious={malicious}",
        f"suspicious={suspicious}",
        f"harmless={harmless}",
        f"undetected={undetected}",
    ]
    if timeout:
        parts.append(f"timeout={timeout}")
    if failure:
        parts.append(f"failure={failure}")
    if reputation != "":
        parts.append(f"reputation={reputation}")
    if threat_label:
        parts.append(f"threat={threat_label}")
    if meaningful:
        parts.append(f"name={meaningful}")
    elif names:
        parts.append(f"name={names[0]}")
    return ", ".join(parts)


def vt_exception_to_result(exc: Exception) -> str:
    name = exc.__class__.__name__
    code = str(getattr(exc, "code", "") or "")
    msg = str(getattr(exc, "message", "") or str(exc) or "")
    low = f"{code} {msg}".lower()
    if "notfound" in low or "not found" in low or "404" in low:
        return "Not found"
    if "wrongcredentials" in low or "unauthorized" in low or "401" in low or "forbidden" in low or "403" in low:
        return "Invalid API key or forbidden"
    if "quota" in low or "rate" in low or "too many" in low or "429" in low:
        return "Rate limited by VirusTotal"
    if "timeout" in low or "timed out" in low:
        return f"VT timeout ({name}): {msg}"
    return f"VT error ({name}): {msg}"


def virustotal_lookup_sha256(sha256: str, event_cb=None, source: str = "manual") -> str:
    sha256 = (sha256 or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", sha256):
        result = "Invalid SHA256"
        if event_cb:
            event_cb("Error", sha256, result, source, False)
        return result

    if sha256 in _vt_cache:
        result = _vt_cache[sha256]
        if event_cb:
            event_cb("Cache", sha256, result, source, True)
        return result

    if vt is None:
        result = "vt-py not installed. Run: python -m pip install vt-py"
        if event_cb:
            event_cb("Error", sha256, result, source, False)
        return result

    api_key = get_virustotal_api_key()
    if not api_key:
        result = "No VirusTotal API key loaded"
        if event_cb:
            event_cb("Error", sha256, result, source, False)
        return result

    if event_cb:
        event_cb("Queued", sha256, "Queued for VirusTotal hash lookup", source, False)

    wait_for_vt_slot(event_cb=event_cb, sha256=sha256, source=source)

    client = None
    try:
        client = vt.Client(api_key, agent=f"{APP_TITLE}/{APP_VERSION}", timeout=45, trust_env=True)
        try:
            response = client.get_json("/files/{}", sha256)
        except Exception as first_exc:
            try:
                response = client.get_json(f"/files/{sha256}")
            except Exception:
                raise first_exc
        result = parse_vt_response(response)
    except Exception as exc:
        result = vt_exception_to_result(exc)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    _vt_cache[sha256] = result
    if event_cb:
        verdict = classify_vt_result(result)
        event_cb("Result" if verdict not in {"Error", "Unknown"} else "Error", sha256, result, source, False)
    return result


def classify_vt_result(text: str) -> str:
    text = (text or "").strip()
    low = text.lower()
    if not text:
        return "Unknown"
    if "not found" in low:
        return "Not Found"
    if (
        low.startswith("vt error") or low.startswith("vt timeout") or
        "invalid api key" in low or "no virustotal api key" in low or
        "not installed" in low or "rate limited" in low
    ):
        return "Error"
    m = re.search(r"malicious=(\d+), suspicious=(\d+)", text)
    if not m:
        return "Unknown"
    malicious = int(m.group(1))
    suspicious = int(m.group(2))
    if malicious > 0:
        return "Malicious"
    if suspicious > 0:
        return "Suspicious"
    return "Clean"


def apply_vt_to_severity(severity: str, suspicious: str, vt_result: str) -> Tuple[str, str]:
    m = re.search(r"malicious=(\d+), suspicious=(\d+)", vt_result or "")
    if not m:
        return severity, suspicious
    malicious = int(m.group(1))
    suspicious_count = int(m.group(2))
    if malicious > 0 or suspicious_count > 0:
        note = f"VirusTotal detection: {vt_result}"
        suspicious = f"{suspicious}; {note}".strip("; ")
        severity = "High" if malicious > 0 else ("Medium" if severity == "Normal" else severity)
    return severity, suspicious


def score_suspicion(name: str, command: str = "", path: str = "", signature_status: str = "", is_process: bool = False, connections: str = "") -> Tuple[str, str]:
    reasons: List[str] = []
    haystack = f"{name} {command} {path}".lower()
    basename = os.path.basename(path or name).lower()
    expanded_path = os.path.expandvars(path).lower() if path else ""

    if path and path.lower() not in {"system", "registry"}:
        if re.match(r"^[a-z]:\\", expanded_path) and not os.path.exists(path):
            reasons.append("path not found")

    if any(part in haystack for part in SUSPICIOUS_DIR_PARTS):
        reasons.append("runs from writable/user/temp location")

    if basename in LIVING_OFF_THE_LAND or re.search(r"\b(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic)\b", haystack):
        reasons.append("living-off-the-land interpreter/tool")

    if re.search(r"-enc\b|-encodedcommand\b|frombase64string|iex\b|invoke-expression|downloadstring|bitsadmin|certutil\s+-urlcache", haystack):
        reasons.append("encoded/download/execution pattern")

    if any(re.match(pattern, basename, re.I) for pattern in SUSPICIOUS_NAME_PATTERNS):
        reasons.append("randomized or impersonating process name")

    if basename in WINDOWS_SYSTEM_NAMES and expanded_path:
        if basename == "explorer.exe":
            if expanded_path != "c:\\windows\\explorer.exe":
                reasons.append("Windows-like name outside expected Windows path")
        elif not any(expanded_path.startswith(root) for root in GOOD_WINDOWS_PATH_PREFIXES):
            reasons.append("Windows-like name outside expected Windows path")

    if signature_status and signature_status not in {"Valid", "Unavailable"}:
        reasons.append(f"signature status: {signature_status}")

    if is_process and not path:
        reasons.append("process path unavailable")

    if connections:
        low = connections.lower()
        if any(port in low for port in [":4444", ":1337", ":31337", ":6667"]):
            reasons.append("connection to commonly abused port")

    reasons = list(dict.fromkeys(reasons))
    if len(reasons) >= 3:
        return "; ".join(reasons), "High"
    if reasons:
        return "; ".join(reasons), "Medium"
    return "", "Normal"


REGISTRY_STARTUP_LOCATIONS: List[Tuple[str, object, str]] = []
if winreg:
    REGISTRY_STARTUP_LOCATIONS = [
        ("HKCU Run", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU RunOnce", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKCU Policies Explorer Run", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        ("HKLM Run", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM RunOnce", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM Policies Explorer Run", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        ("HKLM Wow6432 Run", winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM Wow6432 RunOnce", winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("Winlogon", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ("AppInit DLLs", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
    ]


def enrich_file(path: str, enable_vt: bool, vt_event_cb=None, vt_source: str = "scan") -> Tuple[str, str, str, str]:
    signer = ""
    sig_status = "Unavailable"
    sha = ""
    vt_result = ""
    path = normalize_path(path)
    if path and os.path.isfile(path):
        signer, sig_status = authenticode_signature(path)
        sha = file_sha256(path)
        if enable_vt and sha:
            vt_result = virustotal_lookup_sha256(sha, event_cb=vt_event_cb, source=vt_source)
    return signer, sig_status, sha, vt_result


def make_startup_item(category: str, name: str, command: str, source: str, enable_vt: bool = False, vt_event_cb=None) -> StartupItem:
    path = extract_executable(command)
    signer, sig_status, sha, vt_result = enrich_file(path, enable_vt, vt_event_cb, "startup scan")
    suspicious, severity = score_suspicion(name, command, path, sig_status)
    severity, suspicious = apply_vt_to_severity(severity, suspicious, vt_result)
    return StartupItem(severity, category, name, path, command, source, signer, sig_status, sha, vt_result, suspicious)


def read_registry_values(enable_vt: bool = False, vt_event_cb=None) -> List[StartupItem]:
    rows: List[StartupItem] = []
    if not winreg:
        return rows

    def enum_values(root, subkey, label):
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    if label == "Winlogon" and value_name not in {"Shell", "Userinit", "Notify"}:
                        continue
                    if label == "AppInit DLLs" and value_name not in {"AppInit_DLLs", "LoadAppInit_DLLs"}:
                        continue
                    rows.append(make_startup_item("Registry", value_name, str(value_data), f"{label}: {subkey}", enable_vt, vt_event_cb))
        except PermissionError:
            rows.append(StartupItem("Medium", "Registry", "Permission denied", "", "Run as Administrator", f"{label}: {subkey}", "", "Unavailable", "", "", "could not read protected key"))
        except FileNotFoundError:
            pass
        except Exception as exc:
            rows.append(StartupItem("Medium", "Registry", "Read error", "", str(exc), f"{label}: {subkey}", "", "Unavailable", "", "", "registry read error"))

    for label, root, subkey in REGISTRY_STARTUP_LOCATIONS:
        enum_values(root, subkey, label)

    ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as parent:
            idx = 0
            while True:
                try:
                    child = winreg.EnumKey(parent, idx)
                    idx += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(parent, child) as ck:
                        dbg, _ = winreg.QueryValueEx(ck, "Debugger")
                        row = make_startup_item("Registry", child, str(dbg), f"IFEO Debugger: {ifeo}\\{child}", enable_vt, vt_event_cb)
                        row.suspicious = f"{row.suspicious}; IFEO Debugger persistence".strip("; ")
                        row.severity = "Medium" if row.severity == "Normal" else row.severity
                        rows.append(row)
                except Exception:
                    continue
    except Exception:
        pass

    return rows


def scan_startup_folders(enable_vt: bool = False, vt_event_cb=None) -> List[StartupItem]:
    folders = [
        Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
        Path(os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
    ]
    rows: List[StartupItem] = []
    for folder in folders:
        if folder.exists():
            for item in folder.glob("**/*"):
                if item.is_file():
                    rows.append(make_startup_item("Startup Folder", item.name, str(item), str(folder), enable_vt, vt_event_cb))
    return rows


def scan_scheduled_tasks(enable_vt: bool = False, vt_event_cb=None) -> List[StartupItem]:
    script = r"""
    $tasks = Get-ScheduledTask | ForEach-Object {
      $t = $_
      foreach ($a in $t.Actions) {
        [pscustomobject]@{
          TaskName = $t.TaskName
          TaskPath = $t.TaskPath
          State = $t.State.ToString()
          Execute = $a.Execute
          Arguments = $a.Arguments
          WorkingDirectory = $a.WorkingDirectory
        }
      }
    }
    $tasks | ConvertTo-Json -Depth 4
    """
    rows: List[StartupItem] = []
    for t in powershell_json(script, timeout=90):
        name = f"{t.get('TaskPath','')}{t.get('TaskName','')}"
        cmd = " ".join(str(t.get(k) or "") for k in ["Execute", "Arguments", "WorkingDirectory"]).strip()
        rows.append(make_startup_item("Scheduled Task", name, cmd, f"Scheduled Tasks ({t.get('State','')})", enable_vt, vt_event_cb))
    return rows


def scan_services(enable_vt: bool = False, vt_event_cb=None) -> List[StartupItem]:
    script = r"""
    Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | ConvertTo-Json -Depth 3
    """
    rows: List[StartupItem] = []
    for s in powershell_json(script, timeout=90):
        if str(s.get("StartMode", "")).lower() not in {"auto", "automatic"}:
            continue
        name = f"{s.get('Name','')} - {s.get('DisplayName','')}"
        cmd = str(s.get("PathName") or "")
        rows.append(make_startup_item("Auto Service", name, cmd, f"Win32_Service: {s.get('State','')} / {s.get('StartName','')}", enable_vt, vt_event_cb))
    return rows


def scan_wmi_persistence(enable_vt: bool = False, vt_event_cb=None) -> List[StartupItem]:
    script = r"""
    $items = @()
    try {
      $consumers = Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
      foreach ($c in $consumers) {
        $items += [pscustomobject]@{Name=$c.Name; Command=$c.CommandLineTemplate; Source='WMI CommandLineEventConsumer'}
      }
    } catch {}
    $items | ConvertTo-Json -Depth 4
    """
    rows: List[StartupItem] = []
    for w in powershell_json(script, timeout=60):
        row = make_startup_item("WMI Persistence", str(w.get("Name") or ""), str(w.get("Command") or ""), str(w.get("Source") or "WMI"), enable_vt, vt_event_cb)
        row.suspicious = f"{row.suspicious}; WMI persistence mechanism".strip("; ")
        row.severity = "Medium" if row.severity == "Normal" else row.severity
        rows.append(row)
    return rows


def scan_startup_items(enable_vt: bool = False, vt_event_cb=None) -> List[StartupItem]:
    rows: List[StartupItem] = []
    for scanner in [read_registry_values, scan_startup_folders, scan_scheduled_tasks, scan_services, scan_wmi_persistence]:
        try:
            rows.extend(scanner(enable_vt, vt_event_cb))
        except Exception as exc:
            rows.append(StartupItem("Medium", "Scanner Error", scanner.__name__, "", str(exc), scanner.__name__, "", "Unavailable", "", "", "scanner failed"))
    rank = {"High": 0, "Medium": 1, "Normal": 2}
    return sorted(rows, key=lambda r: (rank.get(r.severity, 3), r.category, r.name.lower()))


def process_connections(pid: int) -> str:
    if not psutil:
        return ""
    try:
        conns = []
        proc = psutil.Process(pid)
        for c in proc.net_connections(kind="inet")[:20]:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            status = c.status or ""
            if raddr:
                conns.append(f"{laddr}->{raddr} {status}")
            elif laddr:
                conns.append(f"{laddr} {status}")
        return "; ".join(conns)
    except Exception:
        return ""


def processes_from_cim() -> Dict[int, Dict[str, str]]:
    script = r"""
    Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Depth 3
    """
    data: Dict[int, Dict[str, str]] = {}
    for p in powershell_json(script, timeout=90):
        try:
            pid = int(p.get("ProcessId"))
            data[pid] = {k: str(v or "") for k, v in p.items()}
        except Exception:
            continue
    return data


def processes_from_psutil(enable_vt: bool = False, vt_event_cb=None) -> List[ProcessItem]:
    rows: List[ProcessItem] = []
    if not psutil:
        return rows
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "status", "create_time"]):
        try:
            info = proc.info
            pid = int(info.get("pid") or 0)
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])
            username = info.get("username") or ""
            status = info.get("status") or ""
            created = ""
            if info.get("create_time"):
                created = dt.datetime.fromtimestamp(info["create_time"]).strftime("%Y-%m-%d %H:%M:%S")
            conns = process_connections(pid)
            signer, sig_status, sha, vt_result = enrich_file(exe, enable_vt, vt_event_cb, "process scan")
            suspicious, severity = score_suspicion(name, cmdline, exe, sig_status, is_process=True, connections=conns)
            severity, suspicious = apply_vt_to_severity(severity, suspicious, vt_result)
            rows.append(ProcessItem(severity, pid, int(info.get("ppid") or 0), name, exe, username, status, created, signer, sig_status, sha, vt_result, conns, suspicious, cmdline))
        except Exception:
            continue
    return rows


def scan_processes(enable_vt: bool = False, vt_event_cb=None) -> List[ProcessItem]:
    rows = processes_from_psutil(enable_vt, vt_event_cb)
    cim = processes_from_cim()

    if not rows:
        for pid, p in cim.items():
            name = p.get("Name", "")
            exe = p.get("ExecutablePath", "")
            cmd = p.get("CommandLine", "")
            signer, sig_status, sha, vt_result = enrich_file(exe, enable_vt, vt_event_cb, "process scan")
            suspicious, severity = score_suspicion(name, cmd, exe, sig_status, is_process=True)
            severity, suspicious = apply_vt_to_severity(severity, suspicious, vt_result)
            rows.append(ProcessItem(severity, pid, int(p.get("ParentProcessId") or 0), name, exe, "", "", p.get("CreationDate", ""), signer, sig_status, sha, vt_result, "", suspicious, cmd))
    else:
        ps_pids = {r.pid for r in rows}
        cim_pids = set(cim.keys())
        for r in rows:
            if r.pid not in cim_pids:
                r.suspicious = f"{r.suspicious}; seen by psutil but not CIM".strip("; ")
                if r.severity == "Normal":
                    r.severity = "Medium"
            elif not r.exe and cim[r.pid].get("ExecutablePath"):
                r.exe = cim[r.pid].get("ExecutablePath", "")
        for pid in sorted(cim_pids - ps_pids):
            p = cim[pid]
            name = p.get("Name", "")
            exe = p.get("ExecutablePath", "")
            cmd = p.get("CommandLine", "")
            signer, sig_status, sha, vt_result = enrich_file(exe, enable_vt, vt_event_cb, "process scan")
            suspicious, severity = score_suspicion(name, cmd, exe, sig_status, is_process=True)
            suspicious = f"{suspicious}; seen by CIM but not psutil".strip("; ")
            if severity == "Normal":
                severity = "Medium"
            severity, suspicious = apply_vt_to_severity(severity, suspicious, vt_result)
            rows.append(ProcessItem(severity, pid, int(p.get("ParentProcessId") or 0), name, exe, "", "", p.get("CreationDate", ""), signer, sig_status, sha, vt_result, "", suspicious, cmd))

    rank = {"High": 0, "Medium": 1, "Normal": 2}
    return sorted(rows, key=lambda r: (rank.get(r.severity, 3), r.name.lower(), r.pid))


def network_scan() -> List[NetworkItem]:
    rows: List[NetworkItem] = []
    if not psutil:
        return rows
    proc_names: Dict[int, str] = {}
    for p in psutil.process_iter(["pid", "name"]):
        try:
            proc_names[int(p.info["pid"])] = str(p.info.get("name") or "")
        except Exception:
            pass
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return rows
    for c in conns:
        pid = c.pid or 0
        proc = proc_names.get(pid, "")
        local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        status = c.status or ""
        suspicious = ""
        severity = "Normal"
        if remote and any(remote.endswith(f":{p}") for p in ["4444", "1337", "31337", "6667"]):
            suspicious, severity = "connection to commonly abused port", "Medium"
        rows.append(NetworkItem(severity, pid, proc, local, remote, status, suspicious))
    rank = {"High": 0, "Medium": 1, "Normal": 2}
    return sorted(rows, key=lambda r: (rank.get(r.severity, 3), r.pid, r.remote))


def scan_defender_exclusions() -> List[DefenderExclusion]:
    script = r"""
    try {
      $p = Get-MpPreference
      $items = @()
      foreach ($x in $p.ExclusionPath) {$items += [pscustomobject]@{Kind='Path'; Value=$x}}
      foreach ($x in $p.ExclusionProcess) {$items += [pscustomobject]@{Kind='Process'; Value=$x}}
      foreach ($x in $p.ExclusionExtension) {$items += [pscustomobject]@{Kind='Extension'; Value=$x}}
      foreach ($x in $p.ExclusionIpAddress) {$items += [pscustomobject]@{Kind='IP'; Value=$x}}
      $items | ConvertTo-Json -Depth 3
    } catch {
      [pscustomobject]@{Kind='Error'; Value=$_.Exception.Message} | ConvertTo-Json -Depth 3
    }
    """
    rows: List[DefenderExclusion] = []
    for item in powershell_json(script, timeout=60):
        kind = str(item.get("Kind") or "")
        value = str(item.get("Value") or "")
        rows.append(DefenderExclusion("Medium", kind, value, "Defender exclusion reduces scan coverage" if kind != "Error" else "Could not read Defender exclusions"))
    return rows


def get_process_modules(pid: int) -> List[Tuple[str, str, str, str, str]]:
    rows: List[Tuple[str, str, str, str, str]] = []
    if not psutil:
        return rows
    try:
        proc = psutil.Process(pid)
        seen = set()
        for mmap in proc.memory_maps():
            path = getattr(mmap, "path", "") or ""
            if not path or path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            signer, status = authenticode_signature(path)
            sha = file_sha256(path)
            suspicious, severity = score_suspicion(os.path.basename(path), path=path, signature_status=status)
            rows.append((path, status, signer, sha, suspicious))
    except Exception as exc:
        rows.append(("", "", "", "", f"Could not read modules: {exc}"))
    return rows[:500]


class VirusTotalDashboard(tk.Toplevel):
    def __init__(self, app: "AuditorApp"):
        super().__init__(app)
        self.app = app
        self.title("VirusTotal Dashboard")
        self.geometry("1200x650")
        self.protocol("WM_DELETE_WINDOW", self.hide)

        self.connection_var = tk.StringVar()
        self.current_var = tk.StringVar()
        self.rate_var = tk.StringVar()
        self.counts_var = tk.StringVar()
        self.last_var = tk.StringVar()

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)
        ttk.Label(top, textvariable=self.connection_var).pack(side="left")
        ttk.Button(top, text="Set VT API Key", command=app.set_vt_api_key).pack(side="right", padx=4)
        ttk.Button(top, text="Clear History", command=self.clear_history).pack(side="right", padx=4)
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="right", padx=4)

        stats = ttk.LabelFrame(self, text="Live VirusTotal Stats")
        stats.pack(fill="x", padx=10, pady=6)
        ttk.Label(stats, textvariable=self.current_var).pack(anchor="w", padx=8, pady=2)
        ttk.Label(stats, textvariable=self.rate_var).pack(anchor="w", padx=8, pady=2)
        ttk.Label(stats, textvariable=self.counts_var).pack(anchor="w", padx=8, pady=2)
        ttk.Label(stats, textvariable=self.last_var).pack(anchor="w", padx=8, pady=2)

        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, padx=10, pady=8)
        columns = ["time", "event", "verdict", "source", "cached", "sha256", "result"]
        widths = [145, 90, 100, 120, 70, 430, 560]
        self.tree = ttk.Treeview(frame, columns=columns, show="headings")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        for col, width in zip(columns, widths):
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=width, minwidth=60, stretch=True)

        for tag, color in [("Malicious", RED), ("Suspicious", ORANGE), ("Clean", GREEN), ("Error", RED), ("Queued", ORANGE), ("Waiting", ORANGE), ("Sending", ORANGE)]:
            self.tree.tag_configure(tag, background=color)

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=10, pady=6)
        ttk.Button(bottom, text="Copy Selected", command=self.copy_selected).pack(side="left", padx=4)
        ttk.Label(bottom, text="Only SHA256 hashes are sent. Files are not uploaded.").pack(side="right")

        self.after(1000, self.tick)
        self.refresh()

    def hide(self):
        self.withdraw()

    def tick(self):
        if self.winfo_exists():
            self.refresh()
            self.after(1000, self.tick)

    def clear_history(self):
        self.app.vt_history.clear()
        for k in self.app.vt_stats:
            self.app.vt_stats[k] = 0
        self.app.vt_current = "Idle"
        self.app.vt_last_result = "None"
        self.refresh()

    def refresh(self):
        key_loaded = "YES" if get_virustotal_api_key() else "NO"
        client_loaded = "YES" if vt is not None else "NO - install vt-py"
        self.connection_var.set(f"API key loaded: {key_loaded} | vt-py loaded: {client_loaded}")
        self.current_var.set(f"Current lookup: {self.app.vt_current}")
        used, remaining, reset = vt_rate_state()
        self.rate_var.set(f"Local rate limit: used {used}/4 per 65s | remaining {remaining} | reset in {reset}s")
        st = self.app.vt_stats
        self.counts_var.set(f"Queue: queued={st.get('queued', 0)} pending={st.get('pending', 0)} completed={st.get('completed', 0)} | Results: total={st['total']} clean={st['clean']} malicious={st['malicious']} suspicious={st['suspicious']} not_found={st['not_found']} errors={st['errors']} cached={st['cached']}")
        self.last_var.set(f"Last result: {self.app.vt_last_result}")

        self.tree.delete(*self.tree.get_children())
        for row in reversed(self.app.vt_history[-600:]):
            tag = row.get("verdict") or row.get("event")
            tags = (tag,) if tag in {"Malicious", "Suspicious", "Clean", "Error", "Queued", "Waiting", "Sending"} else ()
            self.tree.insert("", "end", values=[row.get(k, "") for k in ["time", "event", "verdict", "source", "cached", "sha256", "result"]], tags=tags)

    def copy_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], "values")
        self.clipboard_clear()
        self.clipboard_append("\n".join(str(v) for v in values))


class AuditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1600x900")
        self.minsize(1150, 720)

        self.queue: "queue.Queue[Tuple[str, object]]" = queue.Queue()
        self.startup_rows: List[StartupItem] = []
        self.process_rows: List[ProcessItem] = []
        self.network_rows: List[NetworkItem] = []
        self.defender_rows: List[DefenderExclusion] = []
        self.module_rows: List[Tuple[str, str, str, str, str]] = []

        self.vt_dashboard: Optional[VirusTotalDashboard] = None
        self.vt_current = "Idle"
        self.vt_last_result = "None"
        self.vt_history: List[Dict[str, str]] = []
        self.vt_stats = {"total": 0, "clean": 0, "malicious": 0, "suspicious": 0, "not_found": 0, "errors": 0, "cached": 0, "queued": 0, "completed": 0, "pending": 0}

        self._build_ui()
        self.after(150, self._poll_queue)

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)

        self.status_var = tk.StringVar(value=("Administrator: YES" if is_admin() else "Administrator: NO - run as admin for deeper visibility"))
        ttk.Label(top, textvariable=self.status_var).pack(side="left")

        self.enable_vt = tk.BooleanVar(value=False)
        ttk.Button(top, text="Full Scan", command=self.full_scan).pack(side="right", padx=4)
        ttk.Button(top, text="Processes", command=self.scan_processes).pack(side="right", padx=4)
        ttk.Button(top, text="Startup", command=self.scan_startup).pack(side="right", padx=4)
        ttk.Button(top, text="Network", command=self.scan_network).pack(side="right", padx=4)
        ttk.Button(top, text="Defender Exclusions", command=self.scan_defender).pack(side="right", padx=4)
        ttk.Button(top, text="VT Dashboard", command=self.show_vt_dashboard).pack(side="right", padx=4)
        ttk.Button(top, text="Set VT API Key", command=self.set_vt_api_key).pack(side="right", padx=4)
        ttk.Checkbutton(top, text="VT during scans", variable=self.enable_vt).pack(side="right", padx=8)

        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Label(filter_frame, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        entry = ttk.Entry(filter_frame, textvariable=self.filter_var)
        entry.pack(side="left", fill="x", expand=True, padx=6)
        entry.bind("<KeyRelease>", lambda _e: self.refresh_tables())
        ttk.Label(filter_frame, text="Orange = suspicious. Red = high/detected.").pack(side="right")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=8)

        self.startup_tree = self._make_tree("Startup / Persistence",
            ["severity", "category", "name", "path", "signature_status", "signer", "sha256", "virustotal", "command", "source", "suspicious"],
            [80, 140, 240, 330, 120, 280, 430, 300, 390, 300, 360])

        self.proc_tree = self._make_tree("Processes / Task Manager",
            ["severity", "pid", "ppid", "name", "exe", "signature_status", "signer", "sha256", "virustotal", "connections", "username", "status", "created", "suspicious", "cmdline"],
            [80, 70, 70, 180, 330, 120, 280, 430, 300, 380, 180, 100, 160, 360, 520])

        self.network_tree = self._make_tree("Network Connections",
            ["severity", "pid", "process", "local", "remote", "status", "suspicious"],
            [80, 80, 200, 230, 230, 130, 360])

        self.defender_tree = self._make_tree("Defender Exclusions",
            ["severity", "kind", "value", "suspicious"],
            [80, 140, 600, 380])

        self.modules_tree = self._make_tree("Selected Process Modules",
            ["path", "signature_status", "signer", "sha256", "suspicious"],
            [520, 130, 320, 430, 380])

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=10, pady=6)
        ttk.Button(bottom, text="Open Selected Location", command=self.open_selected_location).pack(side="left", padx=4)
        ttk.Button(bottom, text="Copy Selected", command=self.copy_selected).pack(side="left", padx=4)
        ttk.Button(bottom, text="Load Selected Process Modules", command=self.load_selected_modules).pack(side="left", padx=4)
        ttk.Button(bottom, text="VT Lookup Selected", command=self.vt_lookup_selected).pack(side="left", padx=4)
        ttk.Button(bottom, text="VT Queue All Suspicious", command=self.vt_lookup_suspicious_four).pack(side="left", padx=4)
        ttk.Button(bottom, text="Terminate Selected Process", command=self.terminate_selected_process).pack(side="left", padx=4)
        ttk.Button(bottom, text="Export CSV", command=self.export_csv).pack(side="left", padx=4)
        self.progress = ttk.Progressbar(bottom, mode="indeterminate")
        self.progress.pack(side="right", fill="x", expand=True, padx=8)

        for tree in [self.startup_tree, self.proc_tree, self.network_tree, self.defender_tree]:
            tree.tag_configure("Medium", background=ORANGE)
            tree.tag_configure("High", background=RED)

    def _make_tree(self, title: str, columns: List[str], widths: List[int]) -> ttk.Treeview:
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text=title)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        for col, width in zip(columns, widths):
            tree.heading(col, text=col.title())
            tree.column(col, width=width, minwidth=50, stretch=True)
        return tree

    def _start_worker(self, label: str, target):
        self.status_var.set(label)
        self.progress.start(10)
        threading.Thread(target=target, daemon=True).start()

    def vt_event_cb(self, event: str, sha: str, detail: str, source: str, cached: bool = False):
        self.queue.put(("vt_event", (event, sha, detail, source, cached)))

    def scan_startup(self):
        def worker():
            self.queue.put(("startup", scan_startup_items(self.enable_vt.get(), self.vt_event_cb if self.enable_vt.get() else None)))
        self._start_worker("Scanning startup and persistence locations...", worker)

    def scan_processes(self):
        def worker():
            self.queue.put(("processes", scan_processes(self.enable_vt.get(), self.vt_event_cb if self.enable_vt.get() else None)))
        self._start_worker("Scanning processes...", worker)

    def scan_network(self):
        def worker():
            self.queue.put(("network", network_scan()))
        self._start_worker("Scanning network connections...", worker)

    def scan_defender(self):
        def worker():
            self.queue.put(("defender", scan_defender_exclusions()))
        self._start_worker("Scanning Defender exclusions...", worker)

    def full_scan(self):
        def worker():
            evt = self.vt_event_cb if self.enable_vt.get() else None
            self.queue.put(("startup", scan_startup_items(self.enable_vt.get(), evt)))
            self.queue.put(("processes", scan_processes(self.enable_vt.get(), evt)))
            self.queue.put(("network", network_scan()))
            self.queue.put(("defender", scan_defender_exclusions()))
            self.queue.put(("done", None))
        self._start_worker("Running full scan...", worker)

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "startup":
                    self.startup_rows = payload  # type: ignore
                    self.refresh_tables()
                    self.status_var.set(f"Startup scan complete: {len(self.startup_rows)} items")
                    self.progress.stop()
                elif kind == "processes":
                    self.process_rows = payload  # type: ignore
                    self.refresh_tables()
                    self.status_var.set(f"Process scan complete: {len(self.process_rows)} processes")
                    self.progress.stop()
                elif kind == "network":
                    self.network_rows = payload  # type: ignore
                    self.refresh_tables()
                    self.status_var.set(f"Network scan complete: {len(self.network_rows)} connections")
                    self.progress.stop()
                elif kind == "defender":
                    self.defender_rows = payload  # type: ignore
                    self.refresh_tables()
                    self.status_var.set(f"Defender exclusions scan complete: {len(self.defender_rows)} entries")
                    self.progress.stop()
                elif kind == "modules":
                    self.module_rows = payload  # type: ignore
                    self.refresh_tables()
                    self.status_var.set(f"Loaded {len(self.module_rows)} module entries")
                    self.progress.stop()
                    self.nb.select(self.modules_tree.master)
                elif kind == "vt_event":
                    event, sha, detail, source, cached = payload  # type: ignore
                    self.record_vt_event(str(event), str(sha), str(detail), str(source), bool(cached))
                elif kind == "vt_result":
                    sha, result, source, cached = payload  # type: ignore
                    self.apply_vt_result(str(sha), str(result), str(source), bool(cached))
                    self.progress.stop()
                elif kind == "vt_queue_progress":
                    _sha, index, total = payload  # type: ignore
                    self.vt_stats["completed"] += 1
                    self.vt_stats["pending"] = max(0, self.vt_stats.get("pending", 0) - 1)
                    self.vt_current = f"Queue progress: {index}/{total} complete"
                    self.refresh_vt_dashboard()
                elif kind == "status":
                    self.status_var.set(str(payload))
                elif kind == "done":
                    self.progress.stop()
                    self.status_var.set("Full scan complete")
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def refresh_tables(self):
        filt = self.filter_var.get().lower().strip()

        def match(values: Iterable[object]) -> bool:
            return not filt or filt in " ".join(str(v) for v in values).lower()

        startup = [[r.severity, r.category, r.name, r.path, r.signature_status, r.signer, r.sha256, r.virustotal, r.command, r.source, r.suspicious] for r in self.startup_rows]
        procs = [[r.severity, r.pid, r.ppid, r.name, r.exe, r.signature_status, r.signer, r.sha256, r.virustotal, r.connections, r.username, r.status, r.created, r.suspicious, r.cmdline] for r in self.process_rows]
        network = [[r.severity, r.pid, r.process, r.local, r.remote, r.status, r.suspicious] for r in self.network_rows]
        defender = [[r.severity, r.kind, r.value, r.suspicious] for r in self.defender_rows]
        modules = [[path, status, signer, sha, suspicious] for path, status, signer, sha, suspicious in self.module_rows]

        self._fill_tree(self.startup_tree, [x for x in startup if match(x)], 0)
        self._fill_tree(self.proc_tree, [x for x in procs if match(x)], 0)
        self._fill_tree(self.network_tree, [x for x in network if match(x)], 0)
        self._fill_tree(self.defender_tree, [x for x in defender if match(x)], 0)
        self._fill_tree(self.modules_tree, [x for x in modules if match(x)], None)

    def _fill_tree(self, tree: ttk.Treeview, rows: List[List[object]], severity_index: Optional[int]):
        tree.delete(*tree.get_children())
        for row in rows:
            tags = ()
            if severity_index is not None:
                sev = str(row[severity_index])
                if sev in {"Medium", "High"}:
                    tags = (sev,)
            tree.insert("", "end", values=row, tags=tags)

    def selected_tree(self) -> ttk.Treeview:
        tab_text = self.nb.tab(self.nb.select(), "text")
        if "Processes" in tab_text:
            return self.proc_tree
        if "Network" in tab_text:
            return self.network_tree
        if "Defender" in tab_text:
            return self.defender_tree
        if "Modules" in tab_text:
            return self.modules_tree
        return self.startup_tree

    def selected_values(self) -> Optional[List[str]]:
        tree = self.selected_tree()
        selected = tree.selection()
        if not selected:
            return None
        return [str(v) for v in tree.item(selected[0], "values")]

    def selected_sha256(self) -> str:
        tree = self.selected_tree()
        values = self.selected_values()
        if not values:
            return ""
        if tree is self.startup_tree and len(values) > 6:
            return values[6].strip().lower()
        if tree is self.proc_tree and len(values) > 7:
            return values[7].strip().lower()
        if tree is self.modules_tree and len(values) > 3:
            return values[3].strip().lower()
        return ""

    def selected_process_pid(self) -> Optional[int]:
        tree = self.selected_tree()
        values = self.selected_values()
        if not values:
            return None
        try:
            if tree in {self.proc_tree, self.network_tree}:
                return int(values[1])
        except Exception:
            return None
        return None

    def open_selected_location(self):
        tree = self.selected_tree()
        values = self.selected_values()
        if not values:
            return
        path = ""
        if tree is self.startup_tree and len(values) > 3:
            path = values[3]
        elif tree is self.proc_tree and len(values) > 4:
            path = values[4]
        elif tree is self.modules_tree and values:
            path = values[0]
        path = normalize_path(path)
        if not path:
            messagebox.showinfo(APP_TITLE, "No file path is available for this item.")
            return
        target = path if os.path.isdir(path) else os.path.dirname(path)
        if target and os.path.exists(target):
            subprocess.Popen(["explorer", target])
        else:
            messagebox.showwarning(APP_TITLE, f"Path does not exist:\n{path}")

    def copy_selected(self):
        values = self.selected_values()
        if not values:
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(values))
        self.status_var.set("Selected details copied.")

    def load_selected_modules(self):
        pid = self.selected_process_pid()
        if not pid:
            messagebox.showinfo(APP_TITLE, "Select a process or network row first.")
            return
        def worker():
            self.queue.put(("modules", get_process_modules(pid)))
        self._start_worker(f"Loading modules for PID {pid}...", worker)

    def set_vt_api_key(self):
        key = simpledialog.askstring(APP_TITLE, "Enter VirusTotal API key. It is kept only in memory.", show="*", parent=self)
        if key is not None:
            set_virustotal_api_key(key)
            self.status_var.set("VirusTotal API key loaded for this session.")
            self.show_vt_dashboard()

    def ensure_vt_key(self) -> bool:
        if get_virustotal_api_key():
            return True
        key = simpledialog.askstring(APP_TITLE, "Enter VirusTotal API key. It is kept only in memory.", show="*", parent=self)
        if not key:
            return False
        set_virustotal_api_key(key)
        return True

    def show_vt_dashboard(self):
        if self.vt_dashboard is None or not self.vt_dashboard.winfo_exists():
            self.vt_dashboard = VirusTotalDashboard(self)
        else:
            self.vt_dashboard.deiconify()
            self.vt_dashboard.lift()
        self.refresh_vt_dashboard()

    def refresh_vt_dashboard(self):
        if self.vt_dashboard is not None and self.vt_dashboard.winfo_exists():
            try:
                self.vt_dashboard.refresh()
            except Exception:
                pass

    def record_vt_event(self, event: str, sha: str, detail: str, source: str, cached: bool = False):
        verdict = classify_vt_result(detail) if event in {"Result", "Error", "Cache"} else ""
        if event == "Cache":
            self.vt_stats["cached"] += 1
        if event in {"Result", "Error", "Cache"}:
            self.vt_stats["total"] += 1
            if verdict == "Clean":
                self.vt_stats["clean"] += 1
            elif verdict == "Malicious":
                self.vt_stats["malicious"] += 1
            elif verdict == "Suspicious":
                self.vt_stats["suspicious"] += 1
            elif verdict == "Not Found":
                self.vt_stats["not_found"] += 1
            elif verdict in {"Error", "Unknown"}:
                self.vt_stats["errors"] += 1
        short = f"{sha[:12]}...{sha[-8:]}" if len(sha) == 64 else sha
        self.vt_current = f"{event}: {short} ({source})"
        self.vt_last_result = detail
        self.vt_history.append({
            "time": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": event,
            "verdict": verdict,
            "source": source,
            "cached": "yes" if cached else "no",
            "sha256": sha,
            "result": detail,
        })
        self.status_var.set(f"VirusTotal {event}: {sha} - {detail}")
        self.refresh_vt_dashboard()

    def vt_lookup_selected(self):
        sha = self.selected_sha256()
        if not re.fullmatch(r"[a-f0-9]{64}", sha or ""):
            messagebox.showinfo(APP_TITLE, "Select a Startup, Process, or Module row with a SHA256 hash first.")
            return
        if not self.ensure_vt_key():
            return
        def worker():
            cached = sha in _vt_cache
            result = virustotal_lookup_sha256(sha, event_cb=self.vt_event_cb, source="selected")
            self.queue.put(("vt_result", (sha, result, "selected", cached)))
        self._start_worker(f"Looking up selected SHA256 on VirusTotal: {sha}", worker)
        self.show_vt_dashboard()

    def vt_lookup_suspicious_four(self):
        """
        Queue every suspicious unique SHA256 hash, then process the queue safely:
        4 VirusTotal lookups per 65 seconds until all queued hashes are complete.
        Cached hashes are answered immediately and do not consume the rate window.
        """
        if not self.ensure_vt_key():
            return

        hashes: List[str] = []
        for r in self.startup_rows:
            if r.severity in {"High", "Medium"} and r.sha256 and not r.virustotal and r.sha256 not in hashes:
                hashes.append(r.sha256)
        for r in self.process_rows:
            if r.severity in {"High", "Medium"} and r.sha256 and not r.virustotal and r.sha256 not in hashes:
                hashes.append(r.sha256)

        if not hashes:
            messagebox.showinfo(APP_TITLE, "No uncached suspicious hashes are available.")
            return

        total = len(hashes)
        self.vt_stats["queued"] += total
        self.vt_stats["pending"] += total
        self.record_vt_event("Queued", "QUEUE", f"Queued {total} suspicious hash(es). Processing 4 every 65 seconds until complete.", "queue all suspicious", False)

        def worker():
            for index, sha in enumerate(hashes, start=1):
                cached = sha in _vt_cache
                remaining_after_this = total - index
                self.queue.put(("status", f"VirusTotal queue {index}/{total}; pending after this: {remaining_after_this}; hash: {sha}"))
                self.vt_event_cb("Queued", sha, f"Queue item {index}/{total}. Pending before lookup: {total - index + 1}", "queue all suspicious", cached)
                result = virustotal_lookup_sha256(sha, event_cb=self.vt_event_cb, source="queue all suspicious")
                self.queue.put(("vt_result", (sha, result, "queue all suspicious", cached)))
                self.queue.put(("vt_queue_progress", (sha, index, total)))
            self.queue.put(("done", None))

        self._start_worker(f"Queued {total} suspicious hash(es) for VirusTotal. Processing 4 every 65 seconds...", worker)
        self.show_vt_dashboard()

    def apply_vt_result(self, sha: str, result: str, source: str, cached: bool):
        for r in self.startup_rows:
            if r.sha256.lower() == sha.lower():
                r.virustotal = result
                r.severity, r.suspicious = apply_vt_to_severity(r.severity, r.suspicious, result)
        for r in self.process_rows:
            if r.sha256.lower() == sha.lower():
                r.virustotal = result
                r.severity, r.suspicious = apply_vt_to_severity(r.severity, r.suspicious, result)
        self.refresh_tables()

    def terminate_selected_process(self):
        pid = self.selected_process_pid()
        if not pid:
            messagebox.showinfo(APP_TITLE, "Select a process row first.")
            return
        if pid in {0, 4}:
            messagebox.showwarning(APP_TITLE, "Refusing to terminate critical system PID.")
            return
        if not messagebox.askyesno(APP_TITLE, f"Terminate PID {pid}?\n\nOnly do this if you know what it is."):
            return
        try:
            if psutil:
                psutil.Process(pid).terminate()
            else:
                run_cmd(["taskkill", "/PID", str(pid), "/T"], timeout=30)
            self.status_var.set(f"Terminate signal sent to PID {pid}.")
            self.scan_processes()
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not terminate PID {pid}:\n{exc}")

    def export_csv(self):
        out = filedialog.asksaveasfilename(title="Export scan results", defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not out:
            return
        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Startup / Persistence"])
            writer.writerow(["Severity", "Category", "Name", "Path", "Signature Status", "Signer", "SHA256", "VirusTotal", "Command", "Source", "Suspicious"])
            for r in self.startup_rows:
                writer.writerow([r.severity, r.category, r.name, r.path, r.signature_status, r.signer, r.sha256, r.virustotal, r.command, r.source, r.suspicious])
            writer.writerow([])
            writer.writerow(["Processes"])
            writer.writerow(["Severity", "PID", "PPID", "Name", "Executable", "Signature Status", "Signer", "SHA256", "VirusTotal", "Connections", "Username", "Status", "Created", "Suspicious", "Command Line"])
            for r in self.process_rows:
                writer.writerow([r.severity, r.pid, r.ppid, r.name, r.exe, r.signature_status, r.signer, r.sha256, r.virustotal, r.connections, r.username, r.status, r.created, r.suspicious, r.cmdline])
            writer.writerow([])
            writer.writerow(["Network Connections"])
            writer.writerow(["Severity", "PID", "Process", "Local", "Remote", "Status", "Suspicious"])
            for r in self.network_rows:
                writer.writerow([r.severity, r.pid, r.process, r.local, r.remote, r.status, r.suspicious])
            writer.writerow([])
            writer.writerow(["Defender Exclusions"])
            writer.writerow(["Severity", "Kind", "Value", "Suspicious"])
            for r in self.defender_rows:
                writer.writerow([r.severity, r.kind, r.value, r.suspicious])
            writer.writerow([])
            writer.writerow(["VirusTotal History"])
            writer.writerow(["Time", "Event", "Verdict", "Source", "Cached", "SHA256", "Result"])
            for r in self.vt_history:
                writer.writerow([r.get("time", ""), r.get("event", ""), r.get("verdict", ""), r.get("source", ""), r.get("cached", ""), r.get("sha256", ""), r.get("result", "")])
        messagebox.showinfo(APP_TITLE, f"Exported:\n{out}")


def main():
    if not is_windows():
        print("This app is designed for Windows 11. Some features require Windows APIs.")
    app = AuditorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
