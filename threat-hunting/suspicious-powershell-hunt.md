Threat Hunt: Suspicious PowerShell Activity

Hypothesis: 
An attacker is using PowerShell to execute malicious commands or download payloads.

Data Source: 
Microsoft Defender / DeviceProcessEvents

KQL Query: 
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "IEX", "Invoke-Expression", "DownloadString")

Analysis: 
We check for encoded or obfuscated PowerShell commands often used in attacks.

Conclusion: 
Encoded PowerShell may indicate malware execution or attack automation.

MITRE ATT&CK: 
T1059.001 - PowerShell
