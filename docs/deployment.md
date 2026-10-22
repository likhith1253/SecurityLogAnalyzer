# Deployment & Monitoring

This guide outlines how to run the Security Log Analyzer in various environments and integrate it into a broader security monitoring pipeline.

## Local Development Execution

For rapid forensic analysis on a local machine:

1. **Compile**: Follow the steps in [setup.md](file:///d:/SecurityLogAnalyzer/docs/setup.md).
2. **Execute**:
   ```bash
   java SecurityLogAnalyzer
   ```
3. **Automated Input**: For batch processing, you can pipe credentials and commands:
   ```bash
   echo -e "username\npassword\n1\n5" | java SecurityLogAnalyzer
   ```

## Production Pipeline Integration

SLA can be integrated into existing monitoring workflows as a secondary analysis layer.

### 1. Log Rotation Integration
Configure your web server (Nginx/Apache) to trigger an SLA scan whenever a log file is rotated. 

**Example Cron Job:**
```bash
0 0 * * * /path/to/analyze_logs.sh
```

### 2. Environment Variables
While SLA primarily use `config.properties`, you can wrap it in a shell script to handle sensitive data via environment variables:

```bash
#!/bin/bash
# analyze_logs.sh
java -Dthread_threshold=${THREAT_LIMIT:-0.85} SecurityLogAnalyzer
```

### 3. Output Consumption
The generated `analysis_report.txt` is designed to be parsed by other tools. Its structured "SUMMARY" sections can be indexed by ELK (Elasticsearch, Logstash, Kibana) or Splunk for long-term trend analysis.

## Security Considerations

- **Credential Safety**: `users.csv` stores salted PBKDF2 hashes (generate one with `java -cp out com.sla.util.PasswordHasher <password>`); plaintext entries are rejected. The bundled demo accounts are for local use only; for anything real, interface with an LDAP/OIDC provider.
- **File Permissions**: Ensure that the `blacklist.txt` and `analysis_report.txt` files have restricted permissions to prevent tampering.
- **Resource Limits**: For extremely high-volume logs (GBs per hour), increase the JVM heap size:
  ```bash
  java -Xmx2g SecurityLogAnalyzer
  ```

## Monitoring & Alerts
The system supports a `LiveAlertCallback`. In a production environment, this can be extended to:
- Send a Slack/Discord notification.
- Trigger a firewall rule update via an API call.
- Email a security investigator.
