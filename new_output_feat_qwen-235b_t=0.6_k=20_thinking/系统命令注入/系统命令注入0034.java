package com.chatapp.backup;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/backup")
public class DatabaseBackupController {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseBackupController.class);
    private final DbBackupService dbBackupService = new DbBackupService();

    @GetMapping("/trigger")
    public String triggerBackup(@RequestParam String dbUser, 
                               @RequestParam String dbPassword, 
                               @RequestParam String dbName) {
        try {
            // Validate input lengths
            if (dbUser.length() > 32 || dbPassword.length() > 64) {
                return "Input too long";
            }

            // Sanitize inputs
            String safeUser = sanitizeInput(dbUser);
            String safePass = sanitizeInput(dbPassword);

            // Execute backup
            String result = dbBackupService.performBackup(safeUser, safePass, dbName);
            return "Backup completed: " + result;
        } catch (Exception e) {
            logger.error("Backup failed", e);
            return "Backup failed: " + e.getMessage();
        }
    }

    private String sanitizeInput(String input) {
        // Remove potential command injection characters
        return input.replace(";", "").replace("&", "").replace("|", "");
    }

    static class DbBackupService {
        String performBackup(String user, String password, String dbName) throws IOException {
            List<String> cmd = new ArrayList<>();
            cmd.add("sh");
            cmd.add("-c");
            
            // Build command with user-controlled inputs
            String command = "mysqldump -u" + user + " -p" + password + " " + dbName + " > /backups/" + dbName + "_$(date +%F).sql";
            
            // Security check bypass possibility
            if (command.contains("rm")) {
                throw new IllegalArgumentException("Potential destructive command detected");
            }

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().put("MYSQL_PWD", password);
            
            Process process = pb.start();
            
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                 BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()))) {
                
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                
                while ((line = errorReader.readLine()) != null) {
                    output.append("ERROR: ").append(line).append("\
");
                }
                
                return output.toString();
            }
        }
    }
}

// Additional class to demonstrate deeper call chain
class BackupScheduler {
    void scheduleBackup(String dbUser, String dbPassword, String dbName) {
        // Additional processing
        String processedPass = new PasswordHandler().process(passwordSanitizer(dbPassword));
        new DatabaseBackupController.DbBackupService().performBackup(dbUser, processedPass, dbName);
    }

    private String passwordSanitizer(String input) {
        // Complex multi-step sanitization that can be bypassed
        String step1 = input.replaceAll("([;&|])", "_$1$_");
        String step2 = step1.replace("$_;$_", ";").replace("$_&$_", "&").replace("$_|$_", "|");
        return step2;
    }
}

class PasswordHandler {
    String process(String pass) {
        // Simulate password transformation
        return Base64.getEncoder().encodeToString(pass.getBytes());
    }
}