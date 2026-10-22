package com.sla.service;

import com.sla.model.Role;
import com.sla.model.User;
import com.sla.util.AnsiColors;
import com.sla.util.PasswordHasher;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class UserAuthService {
    private final Map<String, String> userCredentials = new HashMap<>();
    private final Map<String, User> userProfiles = new HashMap<>();
    private final Scanner scanner;
    private static final String DUMMY_HASH = PasswordHasher.hash("unused");
    
    public UserAuthService(Scanner scanner, String usersFilePath) {
        this.scanner = scanner;
        loadUsersFromFile(usersFilePath);
    }
    
    private void loadUsersFromFile(String filePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            reader.readLine(); // Skip header
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",", 4);
                if (parts.length == 4) {
                    if (!PasswordHasher.isHashed(parts[1])) {
                        System.err.println(AnsiColors.RED + "Skipping user '" + parts[0]
                            + "': password must be a PBKDF2 hash (see README)." + AnsiColors.RESET);
                        continue;
                    }
                    userCredentials.put(parts[0], parts[1]);
                    userProfiles.put(parts[0], new User(parts[0], parts[3], Role.valueOf(parts[2])));
                }
            }
        } catch (IOException e) {
            System.err.println(AnsiColors.RED + "Error loading users from " + filePath + ": " + e.getMessage() + AnsiColors.RESET);
        } catch (IllegalArgumentException e) {
            System.err.println(AnsiColors.RED + "Error parsing user roles: " + e.getMessage() + AnsiColors.RESET);
        }
    }
    
    /** Checks the password against the stored PBKDF2 hash (runs a dummy hash for unknown users). */
    boolean verifyCredentials(String username, String password) {
        String stored = userCredentials.get(username);
        if (stored == null) {
            PasswordHasher.verify(password, DUMMY_HASH);
            return false;
        }
        return PasswordHasher.verify(password, stored);
    }

    public User login() {
        int attempts = 0;
        while (attempts < 3) {
            System.out.print(AnsiColors.CYAN + "Username: " + AnsiColors.RESET);
            String username = scanner.nextLine().trim();
            System.out.print(AnsiColors.CYAN + "Password: " + AnsiColors.RESET);
            String password = scanner.nextLine().trim();
            
            if (verifyCredentials(username, password)) {
                System.out.println(AnsiColors.GREEN_BOLD + "✔ Authentication successful." + AnsiColors.RESET);
                return userProfiles.get(username);
            } else {
                System.out.println(AnsiColors.RED_BOLD + "❌ Authentication failed." + AnsiColors.RESET);
                attempts++;
            }
        }
        return null;
    }
}
