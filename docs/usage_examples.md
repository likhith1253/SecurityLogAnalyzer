# Usage Examples

This page provides concrete examples of how to use the Security Log Analyzer for common forensic tasks.

## 1. Running a Full Forensic Analysis

This is the most common use case, where the system scans the entire log file to identify threats.

**Command:**
1. Start the application: `java SecurityLogAnalyzer`
2. Log in with `admin` credentials.
3. Select **Option 1: Run Full Forensic Analysis**.

**Sample Terminal Output:**
```text
--- PHASE 1: Initializing System ---
✔ Data sources loaded.

--- PHASE 2: Log Processing ---
Inserting 1250 logs into self-balancing tree... ✔ Done.

--- PHASE 3: Running Analysis Engine ---
🚨 LIVE ALERT: IP 192.168.1.10 crossed threat threshold!
✔ Core analysis complete.

--- PHASE 4: Analysis Results ---
=== BLACKLIST SUMMARY ===
Total Blacklisted IPs: 5
Newly Blocked IPs: 1

=== MOST DANGEROUS IP ===
  IP Address: 192.168.1.10
  Location: Los Angeles, US
  Threat Score: 0.95
  Total Intrusions: 12
```

![Sample Report Screenshot](file:///d:/SecurityLogAnalyzer/docs/images/sample_output_report.png)

## 2. Tracing IP Activity

Use this option to see every action taken by a specific suspicious IP.

**Command:**
1. Select **Option 2: Trace IP Activity**.
2. Enter IP: `142.93.125.197`

**Output:**
```text
Activity Trace for 142.93.125.197 (Toronto, CA)
+---------------------+--------+------------------+--------+---------------------+
| Timestamp           | Method | Resource         | Status | Details             |
+---------------------+--------+------------------+--------+---------------------+
| 2026-02-23 10:15:22 | GET    | /login           | 401    | Failed login attempt|
| 2026-02-23 10:15:30 | POST   | /api/config      | 403    | Forbidden access    |
| 2026-02-23 10:15:45 | GET    | /etc/passwd      | 200    | Traversal attempt   |
+---------------------+--------+------------------+--------+---------------------+
```

## 3. Querying Logs by Time Range

Useful for investigating incidents that occurred during a specific window.

**Command:**
1. Select **Option 3: Query Logs by Time Range**.
2. Start: `2026-02-23T10:00:00`
3. End: `2026-02-23T11:00:00`

**Output:**
```text
Found 142 log(s) in the specified time range.
+---------------------+--------------+----------+--------+------------+--------+
| Timestamp           | IP Address   | User     | Method | Path       | Status |
+---------------------+--------------+----------+--------+------------+--------+
| 2026-02-23 10:05:11 | 8.8.8.8      | guest    | GET    | /index.html| 200    |
| 2026-02-23 10:08:44 | 1.1.1.1      | admin    | POST   | /api/v1    | 201    |
+---------------------+--------------+----------+--------+------------+--------+
```
