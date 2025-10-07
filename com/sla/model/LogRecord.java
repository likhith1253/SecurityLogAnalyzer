package com.sla.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LogRecord implements Comparable<LogRecord> {
    public final LocalDateTime timestamp;
    public final String ipSourceAddress;
    public final String username;
    public final String httpMethod;
    public final String requestPath;
    public final int httpStatusCode;
    public final String messageDetails;
    
    public LogRecord(LocalDateTime timestamp, String ipSourceAddress, String username, 
                     String httpMethod, String requestPath, int httpStatusCode, String messageDetails) {
        this.timestamp = timestamp;
        this.ipSourceAddress = ipSourceAddress;
        this.username = username;
        this.httpMethod = httpMethod;
        this.requestPath = requestPath;
        this.httpStatusCode = httpStatusCode;
        this.messageDetails = messageDetails;
    }
    
    @Override
    public int compareTo(LogRecord other) {
        return this.timestamp.compareTo(other.timestamp);
    }
    
    @Override
    public String toString() {
        return String.format("[%s] IP: %-15s | User: %-12s | Method: %-6s | Path: %-30s | Status: %d | Details: %s",
            timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
            ipSourceAddress, username, httpMethod, requestPath, httpStatusCode, messageDetails);
    }
}
