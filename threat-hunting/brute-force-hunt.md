Threat Hunt: Brute Force Attack Detection

Hypothesis: 
An attacker is trying to guess user passwords using repeated login attempts.

Data Source: 
Windows Security Logs (Event ID 4625)

KQL Query: 
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count()
by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10

Analysis: 
We look for repeated failed login attempts from the same IP targeting the same user.

Conclusion: 
High failed login volume may indicate automated password guessing activity.

MITRE ATT&CK: 
T1110 - Brute Force
