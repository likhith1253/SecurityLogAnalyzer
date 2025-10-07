package com.sla.app;

import com.sla.dsa.SelfBalancingSearchTree;
import com.sla.engine.ReportGenerator;
import com.sla.engine.ThreatAnalysisEngine;
import com.sla.model.Geolocation;
import com.sla.model.LogRecord;
import com.sla.model.ScanReport;
import com.sla.model.User;
import com.sla.service.AccessLogParser;
import com.sla.service.BlacklistManager;
import com.sla.service.UserAccessControl;
import com.sla.service.UserAuthService;
import com.sla.util.AnsiColors;
import com.sla.util.ConsoleUIHelper;
import com.sla.util.SampleDataGenerator;
import com.sla.util.UserQueryLogger;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Pattern;

public class MainController {
    private final AppConfiguration appConfig;
    private User currentUser;
    private final Scanner scanner = new Scanner(System.in);
    private final String SECRET_KEY_FOR_CIPHER = "SECRET_KEY_FOR_FLA_v11";
    
    public MainController() {
        this.appConfig = new AppConfiguration("config.properties");
    }
    
    public void run() {
        ConsoleUIHelper.printToolHeader("🕵️ Security Log Analyzer (SLA) v11.0");
        System.out.println(AnsiColors.CYAN + "This tool performs log analysis to detect and report suspicious activities." + AnsiColors.RESET);
        System.out.println(AnsiColors.YELLOW + "Threat Score Blacklist Threshold: " + appConfig.getThreatScoreThreshold() + AnsiColors.RESET);
        
        SampleDataGenerator.generateSampleFiles(appConfig);
        
        UserAuthService authService = new UserAuthService(scanner, appConfig.getUsersFile());
        this.currentUser = authService.login();
        
        if (currentUser == null) {
            System.out.println(AnsiColors.RED_BOLD + "Authentication failed. Exiting." + AnsiColors.RESET);
            return;
        }
        
        UserAccessControl accessControl = new UserAccessControl(currentUser);
        UserQueryLogger queryLogger = new UserQueryLogger(appConfig.getQueryLogFile());
        
        mainMenu(accessControl, queryLogger);
    }
    
    private void mainMenu(UserAccessControl accessControl, UserQueryLogger queryLogger) {
        while (true) {
            System.out.println("\n" + AnsiColors.CYAN_BOLD + "--- Main Menu ---" + AnsiColors.RESET);
            System.out.println("1. Run Full Forensic Analysis");
            System.out.println("2. Trace IP Activity");
            System.out.println("3. Query Logs by Time Range");
            System.out.println("4. Exit");
            System.out.print(AnsiColors.YELLOW + "Select an option: " + AnsiColors.RESET);
            
            String choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    runFullAnalysis(accessControl, queryLogger);
                    break;
                case "2":
                    traceIpPath(accessControl, queryLogger);
                    break;
                case "3":
                    queryLogsByTimeRange(accessControl, queryLogger);
                    break;
                case "4":
                    System.out.println(AnsiColors.CYAN + "Exiting Security Log Analyzer." + AnsiColors.RESET);
                    scanner.close();
                    return;
                default:
                    System.out.println(AnsiColors.RED + "Invalid option." + AnsiColors.RESET);
            }
        }
    }
    
    private void runFullAnalysis(UserAccessControl accessControl, UserQueryLogger queryLogger) {
        queryLogger.log(currentUser, "Ran Full Forensic Analysis");
        long startTime = System.currentTimeMillis();
        
        ConsoleUIHelper.printSectionTitle("PHASE 1: Initializing System");
        BlacklistManager blacklistManager = new BlacklistManager(appConfig.getBlacklistFile(), SECRET_KEY_FOR_CIPHER);
        Map<String, Geolocation> geoData = loadGeoData();
        List<Pattern> confidentialPatterns = loadConfidentialPatterns();
        System.out.println(AnsiColors.GREEN + "✔ Data sources loaded." + AnsiColors.RESET);
        
        ConsoleUIHelper.printSectionTitle("PHASE 2: Log Processing");
        AccessLogParser logParser = new AccessLogParser();
        List<LogRecord> logRecords = logParser.parseLogs(appConfig.getLogFile());
        
        SelfBalancingSearchTree<LogRecord> logTree = new SelfBalancingSearchTree<>();
        System.out.print("Inserting " + logRecords.size() + " logs into self-balancing tree... ");
        for (LogRecord record : logRecords) {
            logTree.insert(record);
        }
        System.out.println(AnsiColors.GREEN + "✔ Done." + AnsiColors.RESET);
        
        ConsoleUIHelper.printSectionTitle("PHASE 3: Running Analysis Engine");
        ThreatAnalysisEngine analysisEngine = new ThreatAnalysisEngine(blacklistManager, geoData, confidentialPatterns, appConfig);
        Set<String> alertedIps = new HashSet<>();
        
        analysisEngine.setLiveAlertCallback((ipAddr, score, ts) -> {
            if (alertedIps.add(ipAddr)) {
                System.out.println(AnsiColors.RED_BOLD + "🚨 LIVE ALERT: IP " + 
                    ConsoleUIHelper.formatIPForDisplay(ipAddr, accessControl, true) + 
                    " crossed threat threshold!" + AnsiColors.RESET);
            }
        });
        
        ScanReport report = analysisEngine.analyze(logTree);
        System.out.println(AnsiColors.GREEN + "✔ Core analysis complete." + AnsiColors.RESET);
        
        long endTime = System.currentTimeMillis();
        report.performanceMetrics.put("Total Analysis Time", String.format("%.2f seconds", (endTime - startTime) / 1000.0));
        report.performanceMetrics.put("Logs Processed", String.valueOf(logRecords.size()));
        
        ConsoleUIHelper.printSectionTitle("PHASE 4: Analysis Results");
        
        // Display all analyzed IPs with their scores
        System.out.println(AnsiColors.CYAN_BOLD + "\n=== ALL ANALYZED IP ADDRESSES ===" + AnsiColors.RESET);
        System.out.println(AnsiColors.YELLOW + "Total unique IPs analyzed: " + report.ipRiskScores.size() + AnsiColors.RESET);
        
        List<String> allIPHeaders = Arrays.asList("IP Address", "Location", "Risk Score", "Status");
        List<List<String>> allIPRows = new ArrayList<>();
        
        for (Map.Entry<String, Double> entry : report.ipRiskScores.entrySet()) {
            String ip = entry.getKey();
            Double score = entry.getValue();
            Geolocation geo = report.ipToGeolocationMap.get(ip);
            String location = geo != null ? geo.city + ", " + geo.country : "Unknown";
            String status = score >= appConfig.getThreatScoreThreshold() ? "BLACKLISTED" : 
                           (score >= 0.5 ? "SUSPICIOUS" : "NORMAL");
            String statusColor = score >= appConfig.getThreatScoreThreshold() ? AnsiColors.RED_BOLD :
                                (score >= 0.5 ? AnsiColors.YELLOW : AnsiColors.GREEN);
            
            allIPRows.add(Arrays.asList(
                ConsoleUIHelper.formatIPForDisplay(ip, accessControl, false),
                location,
                String.format("%.3f", score),
                status
            ));
        }
        
        // Sort by risk score descending
        allIPRows.sort((a, b) -> Double.compare(
            Double.parseDouble(b.get(2)), 
            Double.parseDouble(a.get(2))
        ));
        
        ConsoleUIHelper.displayTable("All IP Addresses", allIPHeaders, allIPRows);
        
        // Display top 10 risky IPs
        System.out.println(AnsiColors.RED_BOLD + "\n=== TOP 10 MOST RISKY IP ADDRESSES ===" + AnsiColors.RESET);
        List<String> topIPHeaders = Arrays.asList("Rank", "IP Address", "Location", "Risk Score", "Events");
        List<List<String>> topIPRows = new ArrayList<>();
        
        int rank = 1;
        for (int i = 0; i < Math.min(10, allIPRows.size()); i++) {
            String ip = allIPRows.get(i).get(0).trim();
            // Find original IP (unredacted) for event count
            String originalIP = findOriginalIP(ip, report.ipRiskScores.keySet());
            Long events = report.suspiciousEventFrequency.getOrDefault(originalIP, 0L);
            
            topIPRows.add(Arrays.asList(
                String.valueOf(rank++),
                allIPRows.get(i).get(0),
                allIPRows.get(i).get(1),
                allIPRows.get(i).get(2),
                String.valueOf(events)
            ));
        }
        
        ConsoleUIHelper.displayTable("High-Risk IP Addresses", topIPHeaders, topIPRows);
        
        // Display geographic hotspots
        System.out.println(AnsiColors.YELLOW_BOLD + "\n=== GEOGRAPHIC HOTSPOTS (Top Threat Origins) ===" + AnsiColors.RESET);
        List<String> hotspotHeaders = Arrays.asList("Rank", "Country", "City", "Suspicious Events", "Threat Level");
        List<List<String>> hotspotRows = new ArrayList<>();
        
        // Aggregate by location
        Map<String, Long> locationThreatMap = new HashMap<>();
        Map<String, String> locationCountryMap = new HashMap<>();
        
        for (Map.Entry<String, Double> entry : report.ipRiskScores.entrySet()) {
            if (entry.getValue() >= 0.5) { // Only suspicious or higher
                Geolocation geo = report.ipToGeolocationMap.get(entry.getKey());
                if (geo != null) {
                    String location = geo.city + ", " + geo.country;
                    locationThreatMap.merge(location, 1L, Long::sum);
                    locationCountryMap.put(location, geo.country);
                }
            }
        }
        
        // Sort and display top hotspots
        locationThreatMap.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(10)
            .forEach(entry -> {
                String[] parts = entry.getKey().split(", ");
                String city = parts[0];
                String country = parts.length > 1 ? parts[1] : "Unknown";
                String threatLevel = entry.getValue() >= 5 ? "HIGH" : 
                                   (entry.getValue() >= 3 ? "MEDIUM" : "LOW");
                hotspotRows.add(Arrays.asList(
                    String.valueOf(hotspotRows.size() + 1),
                    country,
                    city,
                    String.valueOf(entry.getValue()),
                    threatLevel
                ));
            });
        
        ConsoleUIHelper.displayTable("Attack Origin Hotspots", hotspotHeaders, hotspotRows);
        
        // Display blacklist summary
        System.out.println(AnsiColors.RED_BOLD + "\n=== BLACKLIST SUMMARY ===" + AnsiColors.RESET);
        System.out.println(AnsiColors.YELLOW + "Total Blacklisted IPs: " + report.finalBlacklist.size() + AnsiColors.RESET);
        System.out.println(AnsiColors.YELLOW + "Newly Blocked IPs: " + report.newlyBlockedIPs.size() + AnsiColors.RESET);
        
        if (!report.newlyBlockedIPs.isEmpty()) {
            System.out.println(AnsiColors.RED + "\nNewly Blacklisted IPs:" + AnsiColors.RESET);
            for (Map.Entry<String, LocalDateTime> entry : report.newlyBlockedIPs.entrySet()) {
                Geolocation geo = report.ipToGeolocationMap.get(entry.getKey());
                System.out.println(String.format("  • %s (%s) - Blocked at %s",
                    ConsoleUIHelper.formatIPForDisplay(entry.getKey(), accessControl, false),
                    geo != null ? geo.city + ", " + geo.country : "Unknown",
                    entry.getValue().format(DateTimeFormatter.ofPattern("HH:mm:ss"))
                ));
            }
        }
        
        ConsoleUIHelper.printSectionTitle("PHASE 5: Generating Detailed Report File");
        ReportGenerator reportGenerator = new ReportGenerator(appConfig.getReportFile(), accessControl, confidentialPatterns);
        reportGenerator.generate(report, analysisEngine);
        System.out.println(AnsiColors.GREEN_BOLD + "\n✔ Analysis complete. Detailed report saved to '" + appConfig.getReportFile() + "'." + AnsiColors.RESET);
        
        blacklistManager.saveBlacklist();
        saveSuspiciousList(report.finalSuspiciousIps);
    }
    
    private String findOriginalIP(String displayedIP, Set<String> allIPs) {
        String trimmed = displayedIP.trim();
        if (trimmed.endsWith(".XXX")) {
            String prefix = trimmed.substring(0, trimmed.length() - 4);
            for (String ip : allIPs) {
                if (ip.startsWith(prefix)) {
                    return ip;
                }
            }
        }
        return trimmed;
    }
    
    private void traceIpPath(UserAccessControl accessControl, UserQueryLogger queryLogger) {
        System.out.print(AnsiColors.CYAN + "Enter IP address to trace: " + AnsiColors.RESET);
        String ipToTrace = scanner.nextLine().trim();
        queryLogger.log(currentUser, "Traced IP: " + ipToTrace);
        
        AccessLogParser logParser = new AccessLogParser();
        List<LogRecord> allLogs = logParser.parseLogs(appConfig.getLogFile());
        Map<String, Geolocation> geoData = loadGeoData();
        
        List<LogRecord> ipActivity = allLogs.stream()
            .filter(log -> log.ipSourceAddress.equals(ipToTrace))
            .sorted()
            .collect(java.util.stream.Collectors.toList());
        
        if (ipActivity.isEmpty()) {
            System.out.println(AnsiColors.YELLOW + "No activity found for IP: " + ipToTrace + AnsiColors.RESET);
            return;
        }
        
        Geolocation geo = geoData.get(BlacklistManager.getIpPrefix(ipToTrace));
        ConsoleUIHelper.printSectionTitle("Activity Trace for " + ipToTrace + " (" + (geo != null ? geo : "Unknown Location") + ")");
        
        List<String> headers = Arrays.asList("Timestamp", "Method", "Resource", "Status Code", "Details");
        List<List<String>> rows = ipActivity.stream()
            .map(log -> Arrays.asList(
                log.timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                log.httpMethod, log.requestPath, String.valueOf(log.httpStatusCode), log.messageDetails
            )).collect(java.util.stream.Collectors.toList());
        ConsoleUIHelper.displayTable("Chronological Event History", headers, rows);
    }
    
    private void queryLogsByTimeRange(UserAccessControl accessControl, UserQueryLogger queryLogger) {
        queryLogger.log(currentUser, "Queried Logs by Time Range");
        
        System.out.print(AnsiColors.CYAN + "Enter start timestamp (yyyy-MM-ddTHH:mm:ss): " + AnsiColors.RESET);
        String startInput = scanner.nextLine().trim();
        System.out.print(AnsiColors.CYAN + "Enter end timestamp (yyyy-MM-ddTHH:mm:ss): " + AnsiColors.RESET);
        String endInput = scanner.nextLine().trim();
        
        LocalDateTime startTime;
        LocalDateTime endTime;
        
        try {
            startTime = LocalDateTime.parse(startInput, DateTimeFormatter.ISO_DATE_TIME);
            endTime = LocalDateTime.parse(endInput, DateTimeFormatter.ISO_DATE_TIME);
        } catch (DateTimeParseException e) {
            System.out.println(AnsiColors.RED + "Invalid timestamp format. Please use yyyy-MM-ddTHH:mm:ss" + AnsiColors.RESET);
            return;
        }
        
        if (startTime.isAfter(endTime)) {
            System.out.println(AnsiColors.RED + "Start time must be before end time." + AnsiColors.RESET);
            return;
        }
        
        ConsoleUIHelper.printSectionTitle("Loading Logs");
        AccessLogParser logParser = new AccessLogParser();
        List<LogRecord> allLogs = logParser.parseLogs(appConfig.getLogFile());
        
        SelfBalancingSearchTree<LogRecord> logTree = new SelfBalancingSearchTree<>();
        for (LogRecord record : allLogs) {
            logTree.insert(record);
        }
        
        // Use efficient range query O(log N + k)
        LogRecord startKey = new LogRecord(startTime, "", "", "", "", 0, "");
        LogRecord endKey = new LogRecord(endTime, "", "", "", "", 0, "");
        List<LogRecord> results = logTree.rangeQuery(startKey, endKey);
        
        ConsoleUIHelper.printSectionTitle("Time Range Query Results: " + startInput + " to " + endInput);
        System.out.println(AnsiColors.YELLOW + "Found " + results.size() + " log(s) in the specified time range." + AnsiColors.RESET);
        
        if (!results.isEmpty()) {
            List<String> headers = Arrays.asList("Timestamp", "IP Address", "User", "Method", "Path", "Status", "Details");
            List<List<String>> rows = results.stream()
                .map(log -> Arrays.asList(
                    log.timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                    ConsoleUIHelper.formatIPForDisplay(log.ipSourceAddress, accessControl, false),
                    log.username,
                    log.httpMethod,
                    log.requestPath,
                    String.valueOf(log.httpStatusCode),
                    log.messageDetails
                )).collect(java.util.stream.Collectors.toList());
            ConsoleUIHelper.displayTable("Logs in Time Range", headers, rows);
        }
    }
    
    private Map<String, Geolocation> loadGeoData() {
        Map<String, Geolocation> data = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(appConfig.getGeoDataFile()))) {
            reader.readLine(); // Skip header
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",", 3);
                if (parts.length >= 3) {
                    data.put(parts[0], new Geolocation(parts[0], parts[1], parts[2]));
                }
            }
        } catch (IOException e) {
            System.err.println(AnsiColors.YELLOW + "Warning: Could not load geo_data.csv: " + e.getMessage() + AnsiColors.RESET);
        }
        return data;
    }
    
    private List<Pattern> loadConfidentialPatterns() {
        List<Pattern> patterns = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(appConfig.getConfidentialPatternsFile()))) {
            reader.lines()
                .filter(line -> !line.trim().isEmpty() && !line.startsWith("#"))
                .forEach(line -> patterns.add(Pattern.compile(line.trim(), Pattern.CASE_INSENSITIVE)));
        } catch (IOException e) {
            System.err.println(AnsiColors.YELLOW + "Warning: Could not load confidential_data_requests.txt: " + e.getMessage() + AnsiColors.RESET);
        }
        return patterns;
    }
    
    private void saveSuspiciousList(Set<String> suspiciousIps) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(appConfig.getSuspiciousFile(), false))) {
            for (String ip : suspiciousIps) {
                writer.write(ip);
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println(AnsiColors.RED + "Error saving suspicious.txt file: " + e.getMessage() + AnsiColors.RESET);
        }
    }
}
