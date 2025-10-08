# Security Log Analyzer (SLA) v12.0

## Overview
A professional forensic log analysis tool built in Java that uses Red-Black Tree data structure for efficient log processing and threat detection. The application analyzes access logs to identify suspicious activity, detect potential security threats, and generate comprehensive security reports.

## Recent Changes (October 2025)

### Latest Updates - v12.1 (October 8, 2025)
- **Randomized Data Generation**: Logs are now regenerated with random IPs each run for varied blacklist results
  - 20 random high-threat IPs, 25 medium-threat IPs, 30 low-threat IPs per run
  - Fresh blacklist on each analysis for different threat patterns
- **Enhanced Reporting**: After Phase 5, displays:
  - All blacklisted IPs with threat scores and request counts
  - IP with most requests along with location, threat score, and total requests
  - Most dangerous IP with intrusion count
- **Red-Black Tree Fix**: Corrected critical bug in black leaf deletion with proper double-black handling
- **100,000 Log Entries**: Processes 100,000 diverse logs for comprehensive analysis

### Major Refactoring - v12.0
- **Modular Architecture**: Completely restructured from monolithic file to professional package-based architecture
- **Complete Red-Black Tree**: Full implementation with insert, delete, search, min/max, predecessor/successor, range query, and validation
- **New Features**: 
  - "Query Logs by Time Range" using efficient RBT range queries (O(log N + k))
  - "Red-Black Tree Operations Demo" showcasing all RBT operations with performance metrics
- **Enhanced Analysis**: Display all IPs with scores, top 10 risky IPs, and geographic hotspots
- **Security Improvements**: Removed all external API dependencies and hardcoded keys
- **Code Quality**: Improved error handling throughout - no silent exception catches

### Package Structure
```
com.sla.app       - Application controller and configuration
com.sla.model     - Data models (LogRecord, User, ScanReport, etc.)
com.sla.util      - Utility classes (AnsiColors, ConsoleUIHelper, etc.)
com.sla.service   - Business logic services (Auth, Parser, Blacklist, etc.)
com.sla.engine    - Analysis and reporting engine
com.sla.dsa       - Data structures (Red-Black Tree implementation)
```

## Project Architecture

### Core Data Structure
- **Red-Black Tree**: Self-balancing binary search tree for efficient log storage and retrieval
  - Insert: O(log N)
  - Search: O(log N)
  - Range Query: O(log N + k) where k is the number of results

### Key Features
1. **User Authentication**: Role-based access control (ADMIN, INVESTIGATOR, AUDITOR)
2. **Log Analysis**: Risk scoring based on multiple threat indicators
3. **Blacklist Management**: Automatic IP blocking when threat threshold exceeded
4. **Report Generation**: Detailed security analysis reports
5. **IP Tracing**: Track all activity for specific IP addresses
6. **Time Range Queries**: Efficiently query logs within specific time ranges

### Configuration Files
- `config.properties` - Application configuration settings
- `users.csv` - User credentials and roles
- `geo_data.csv` - IP geolocation data
- `confidential_data_requests.txt` - Patterns for confidential resources
- `logs.txt` - Access log entries to analyze

### Output Files
- `analysis_report.txt` - Comprehensive analysis report
- `blacklist.txt` - Encrypted list of blocked IPs
- `suspicious.txt` - List of suspicious IP addresses
- `query_log.txt` - Audit log of user queries

## Running the Application

The application runs automatically in the Replit environment. Default credentials:
- Admin: username=`admin`, password=`admin123`
- Investigator: username=`investigator`, password=`inv123`
- Auditor: username=`auditor`, password=`audit123`

### Menu Options
1. **Run Full Forensic Analysis** - Complete log analysis with threat detection
2. **Trace IP Activity** - View all activity for a specific IP address
3. **Query Logs by Time Range** - Efficiently retrieve logs in a time range (uses RBT range query)
4. **Red-Black Tree Operations Demo** - Showcase all RBT operations with performance metrics
5. **Exit** - Close the application

## Threat Scoring System
- **0.30 points**: Confidential resource access
- **0.25 points**: Explicit attack indicators (SQL injection, directory traversal)
- **0.15 points**: Failed login attempts
- **0.10 points**: Server errors (5xx status codes)
- **0.05 points**: Client errors (4xx status codes)
- **Threshold**: 0.85 (configurable in config.properties)

## Technology Stack
- **Language**: Java 19 (GraalVM)
- **Data Structure**: Custom Red-Black Tree implementation
- **Build System**: Manual compilation with javac
- **Architecture**: Modular package-based design

## Development Notes
- All sample data files are auto-generated on first run if missing
- Blacklist is encrypted using simple XOR cipher for demonstration
- No external dependencies or APIs - fully standalone application
- Comprehensive error handling with informative messages
