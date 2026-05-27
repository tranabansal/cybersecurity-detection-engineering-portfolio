Incident Response Report: Phishing Activity

📌 Summary
A suspected phishing activity was identified where a user likely executed a malicious attachment or link leading to suspicious process execution.

---

⏱️ Timeline
- User received suspicious email (simulated)
- Office application (winword.exe / excel.exe) opened attachment
- Suspicious child process observed (powershell.exe / cmd.exe)

---

🔍 Investigation Steps
- Checked process creation logs (DeviceProcessEvents)
- Identified Office → PowerShell execution chain
- Reviewed command line arguments for encoded or suspicious commands
- Correlated activity with known phishing techniques

---

⚠️ Impact
- Potential execution of malicious payload
- Possible credential theft or system compromise risk

---

🛑 Containment Actions
- Isolate affected endpoint (simulated response)
- Block malicious process execution patterns
- Investigate email source (if available)

---

📚 Lessons Learned
- Office applications should not spawn scripting engines
- Monitoring parent-child process relationships is critical
- Early detection reduces impact of phishing attacks

---

🎯 MITRE ATT&CK
- T1566: Phishing
- T1059: Command and Scripting Interpreter
- T1204: User Execution
