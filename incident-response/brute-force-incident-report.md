Incident Response Report: Brute Force Attack

📌 Summary
Multiple failed login attempts were detected against a user account, indicating a potential brute force attack.

---

⏱️ Timeline
- Multiple Event ID 4625 failures observed
- Same IP address attempted repeated logins
- Activity concentrated within a short time window

---

🔍 Investigation Steps
- Queried SecurityEvent logs for EventID 4625
- Grouped failures by username and IP address
- Identified repeated authentication attempts in short timeframe
- Checked for successful login follow-up (not observed in simulation)

---

⚠️ Impact
- Risk of unauthorized account access
- Potential credential compromise attempt

---

🛑 Containment Actions
- Temporary account lockout (simulated)
- IP blocking recommendation
- Password reset enforcement
- MFA enforcement check

---

📚 Lessons Learned
- Repeated failed logins are early indicators of credential attacks
- Rate limiting and MFA reduce brute force success
- Monitoring authentication spikes is essential in SOC operations

---

🎯 MITRE ATT&CK
- T1110: Brute Force
- T1078: Valid Accounts
