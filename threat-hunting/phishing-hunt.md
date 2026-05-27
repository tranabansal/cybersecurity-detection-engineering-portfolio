Threat Hunt: Suspicious Office Process Execution

Hypothesis: 
A phishing email may have delivered a malicious Office document.

Data Source: 
Windows Process Creation Logs

KQL Query: 
DeviceProcessEvents
| where InitiatingProcessFileName has_any ("winword.exe", "excel.exe", "outlook.exe")
| where FileName has_any ("powershell.exe", "cmd.exe", "wscript.exe")

Analysis: 
We check if Office applications are spawning scripting engines.

Conclusion: 
Office → script execution chain is a strong phishing indicator.

MITRE ATT&CK: 
T1566 - Phishing
T1059 - Command Execution
