# Core Features

Security Log Analyzer (SLA) provides a suite of professional tools for security researchers and system administrators.

## 1. Automated Threat Detection
The system automatically scans log entries for known attack patterns and suspicious behaviors.
- **Heuristic Scoring**: Assigns risk levels based on multiple factors (e.g., status codes, resource sensitivity).
- **Pattern Matching**: Detects SQL Injection, Path Traversal, and credential stuffing attempts.
- **Confidential Resource Protection**: Monitors access to sensitive files like `.env`, `/etc/passwd`, and configuration directories.

## 2. Dynamic Blacklisting
Manage and enforce IP-based security policies.
- **Real-time Blocking**: Automatically blacklists IPs that exceed a defined threat threshold.
- **Persistence**: Saves and loads blacklist state from localized storage.
- **Encrypted Storage**: Utilizes XOR-based obfuscation for sensitive blacklist data.

## 3. Advanced Log Querying
Efficiently search through thousands of logs using optimized data structures.
- **Time-Range Queries**: Search for events between specific timestamps with $O(\log n)$ efficiency.
- **IP Tracing**: Visualize the complete chronological history of a specific IP address.
- **Self-Balancing Storage**: Records are indexed in a Red-Black Tree for consistent performance.

## 4. Comprehensive Reporting
Generate detailed forensic evidence for incident response.
- **Performance Metrics**: Track processing time and log volume.
- **Risk Summaries**: View most dangerous IPs and regional threat distributions.
- **Security Alerts**: Live alerts triggered when critical thresholds are crossed.

## 5. User Access Control (RBAC)
Secure the analyzer itself with robust authentication.
- **Multi-Role Support**: Admin, Investigator, and Auditor roles.
- **Activity Logging**: Tracks all queries and actions taken by the analyzer users.
- **Field-Level Security**: Masks sensitive IP information based on user permissions.
