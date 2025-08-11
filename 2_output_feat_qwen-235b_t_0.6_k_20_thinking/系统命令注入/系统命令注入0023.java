package com.example.backup.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/admin")
public class DatabaseBackupController {

    private final BackupService backupService = new BackupService();

    @PostMapping("/backupdb")
    public String triggerBackup(@RequestParam String backupName) throws IOException {
        return backupService.initiateBackup(backupName);
    }
}

class BackupService {
    private static final String BACKUP_DIR = "/var/backups/db/";

    public String initiateBackup(String userInput) throws IOException {
        if (!isValidBackupName(userInput)) {
            return "Invalid backup name";
        }

        String safePath = sanitizePath(userInput);
        String fullPath = BACKUP_DIR + safePath;

        BackupCommandExecutor executor = new BackupCommandExecutor();
        return executor.executeBackup(fullPath);
    }

    private boolean isValidBackupName(String name) {
        return name.length() >= 3 && name.length() <= 50;
    }

    private String sanitizePath(String path) {
        return path.replace("../", "");
    }
}

class BackupCommandExecutor {
    public String executeBackup(String backupPath) throws IOException {
        String command = String.format("tar -czf %s /data/db", backupPath);
        ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
        Process process = builder.start();

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}