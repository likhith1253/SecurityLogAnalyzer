package com.sla.util;

import com.sla.app.AppConfiguration;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class SampleDataGenerator {
    
    private static final SecureRandom random = new SecureRandom();
    
    public static void generateSampleFiles(AppConfiguration config) {
        // Generate sample files only if they don't exist
        generateUsersFile(config.getUsersFile());
        generateGeoDataFile(config.getGeoDataFile());
        generateConfidentialPatternsFile(config.getConfidentialPatternsFile());
        generateLogsFile(config.getLogFile());
    }
    
    private static void generateUsersFile(String filePath) {
        if (new File(filePath).exists()) {
            return;
        }
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write("username,password,role,userid\n");
            writer.write("admin,admin123,ADMIN,ADM001\n");
            writer.write("investigator,inv123,INVESTIGATOR,INV001\n");
            writer.write("auditor,audit123,AUDITOR,AUD001\n");
        } catch (IOException e) {
            System.err.println(AnsiColors.RED + "Warning: Could not generate " + filePath + ": " + e.getMessage() + AnsiColors.RESET);
        }
    }
    
    private static void generateGeoDataFile(String filePath) {
        if (new File(filePath).exists()) {
            return;
        }
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write("ip_prefix,country,city\n");
            writer.write("192.168.1,USA,New York\n");
            writer.write("10.0.0,USA,San Francisco\n");
            writer.write("172.16.0,UK,London\n");
            writer.write("103.137.185,CN,Beijing\n");
            writer.write("104.248.4,DE,Berlin\n");
            writer.write("5.188.86,RU,Moscow\n");
            writer.write("81.169.144,DE,Frankfurt\n");
        } catch (IOException e) {
            System.err.println(AnsiColors.RED + "Warning: Could not generate " + filePath + ": " + e.getMessage() + AnsiColors.RESET);
        }
    }
    
    private static void generateConfidentialPatternsFile(String filePath) {
        if (new File(filePath).exists()) {
            return;
        }
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write("/admin\n");
            writer.write("/config\n");
            writer.write("/secret\n");
            writer.write("/private\n");
            writer.write("\\.env\n");
            writer.write("/credentials\n");
        } catch (IOException e) {
            System.err.println(AnsiColors.RED + "Warning: Could not generate " + filePath + ": " + e.getMessage() + AnsiColors.RESET);
        }
    }
    
    private static void generateLogsFile(String filePath) {
        if (new File(filePath).exists()) {
            return;
        }
        
        String[] ips = {"192.168.1.10", "10.0.0.5", "172.16.0.20", "103.137.185.155", "104.248.4.72", "5.188.86.139"};
        String[] users = {"alice", "bob", "charlie", "-", "-"};
        String[] methods = {"GET", "POST", "PUT", "DELETE"};
        String[] paths = {"/api/login", "/admin/dashboard", "/config/settings", "/api/data", "/secret/key", "/public/info"};
        int[] statusCodes = {200, 201, 400, 401, 403, 404, 500};
        String[] details = {"Success", "Failed login", "SQL injection attempt", "Traversal attempt", "Unauthorized access"};
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            LocalDateTime baseTime = LocalDateTime.now().minusHours(2);
            
            for (int i = 0; i < 100; i++) {
                LocalDateTime timestamp = baseTime.plusMinutes(i);
                String ip = ips[random.nextInt(ips.length)];
                String user = users[random.nextInt(users.length)];
                String method = methods[random.nextInt(methods.length)];
                String path = paths[random.nextInt(paths.length)];
                int status = statusCodes[random.nextInt(statusCodes.length)];
                String detail = details[random.nextInt(details.length)];
                
                writer.write(String.format("%s,%s,%s,%s,%s,%d,%s\n",
                    timestamp.format(DateTimeFormatter.ISO_DATE_TIME),
                    ip, user, method, path, status, detail));
            }
        } catch (IOException e) {
            System.err.println(AnsiColors.RED + "Warning: Could not generate " + filePath + ": " + e.getMessage() + AnsiColors.RESET);
        }
    }
}
