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
   javac -encoding UTF-8 -d . SecurityLogAnalyzer.java com/sla/app/*.java com/sla/dsa/*.java com/sla/engine/*.java com/sla/model/*.java com/sla/service/*.java com/sla/util/*.java
   ```

## Configuration

The system behavior can be tuned in `config.properties`:

| Property | Description | Default |
| :--- | :--- | :--- |
| `threat_score_threshold` | Score (0.0 - 1.0) above which an IP is blacklisted | `0.85` |
| `log_file_path` | Path to the source log file for analysis | `sample.log` |
| `report_output_file` | Destination for the generated forensic report | `security_report.txt` |
| `users_file` | CSV file containing authorized analyzer users | `users.csv` |

## Supplying Log Files

The analyzer treats the file specified in `log_file_path` as the primary ingestion source. You can point this to your production web server logs (Apache, Nginx, etc.) as long as they follow standard formatting.

> [!TIP]
> Use the `SampleDataGenerator` utility within the application to generate a demo log file if you don't have one ready.
