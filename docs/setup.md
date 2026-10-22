# System Configuration & Setup

This guide provides instructions for setting up the Security Log Analyzer (SLA) environment and running the application.

## Prerequisites

- **Java Development Kit (JDK) 11 or higher**: The project uses modern Java features and requires a compatible runtime.
- **Terminal/Command Line**: Access to a shell for executing commands.

## Installation

1. **Download the Repository**
   Ensure all source files and data directories are present in the project root.

2. **Directory Structure**
   Verify the presence of the following files in the root:
   - `users.csv` (Authentication data)
   - `geo_data.csv` (IP Geolocation database)
   - `config.properties` (System configuration)
   - `confidential_data_requests.txt` (Detection patterns)

3. **Compilation**
   Compile the source code from the project root:
   ```bash
   mkdir out
   javac -encoding UTF-8 -d out SecurityLogAnalyzer.java com/sla/*/*.java
   java -cp out SecurityLogAnalyzer
   ```

## Configuration

The system behavior can be tuned in `config.properties`:

| Property | Description | Default |
| :--- | :--- | :--- |
| `threat.score.threshold` | Score (0.0 - 1.0) above which an IP is blacklisted | `0.85` |
| `log.file` | Log file to analyze (regenerated with random sample data on each start) | `logs.txt` |
| `report.file` | Destination for the generated forensic report | `analysis_report.txt` |
| `users.file` | CSV of users with PBKDF2 password hashes | `users.csv` |
| `blacklist.file`, `suspicious.file`, `query.log.file` | Runtime output files | see `config.properties` |

## Supplying Log Files

The analyzer treats the file specified in `log_file_path` as the primary ingestion source. You can point this to your production web server logs (Apache, Nginx, etc.) as long as they follow standard formatting.

> [!TIP]
> Use the `SampleDataGenerator` utility within the application to generate a demo log file if you don't have one ready.
