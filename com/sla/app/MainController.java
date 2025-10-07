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
        
        ConsoleUIHelper.printSectionTitle("PHASE 4: Generating Report");
        ReportGenerator reportGenerator = new ReportGenerator(appConfig.getReportFile(), accessControl, confidentialPatterns);
        reportGenerator.generate(report, analysisEngine);
        System.out.println(AnsiColors.GREEN_BOLD + "\n✔ Analysis complete. Report saved to '" + appConfig.getReportFile() + "'." + AnsiColors.RESET);
        
        blacklistManager.saveBlacklist();
        saveSuspiciousList(report.finalSuspiciousIps);
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
