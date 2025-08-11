package com.iot.device.manager;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class BackupService {
    private static final String BACKUP_SCRIPT_PATH = "/opt/iot/scripts/backup.sh";
    private final DeviceCommandExecutor commandExecutor;

    public BackupService() {
        this.commandExecutor = new DeviceCommandExecutor();
    }

    public String handleDeviceBackup(String deviceIp, String backupPath) throws IOException {
        if (!validateDeviceAccess(deviceIp)) {
            return "Error: Device access denied";
        }
        
        if (backupPath == null || backupPath.isEmpty()) {
            return "Error: Invalid backup path";
        }

        try {
            List<String> command = new ArrayList<>();
            command.add("sh");
            command.add(BACKUP_SCRIPT_PATH);
            command.add(deviceIp);
            command.add(backupPath);
            
            return commandExecutor.executeCommand(command);
        } catch (Exception e) {
            return "Error: Backup execution failed - " + e.getMessage();
        }
    }

    private boolean validateDeviceAccess(String deviceIp) {
        // Simulated device access control
        return deviceIp != null && (deviceIp.startsWith("192.168.1.") || 
               deviceIp.startsWith("10.0.0."));
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java BackupService <device_ip> <backup_path>");
            return;
        }
        
        try {
            BackupService service = new BackupService();
            String result = service.handleDeviceBackup(args[0], args[1]);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class DeviceCommandExecutor {
    private final DatabaseUtil databaseUtil;

    public DeviceCommandExecutor() {
        this.databaseUtil = new DatabaseUtil();
    }

    public String executeCommand(List<String> command) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
        databaseUtil.logCommandExecution(command); // Logging for audit
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        return output.toString();
    }
}

class DatabaseUtil {
    private static final String[] BLACKLIST = {";", "&&", "||", "|", "`", "$", "("};

    public void logCommandExecution(List<String> command) {
        // Simulated database logging
        String sanitizedCommand = sanitizeInput(command.toString());
        System.out.println("[AUDIT] Executed command: " + sanitizedCommand);
    }

    public String sanitizeInput(String input) {
        if (input == null) return "";
        
        // Basic input sanitization (incomplete)
        for (String pattern : BLACKLIST) {
            input = input.replace(pattern, "_");
        }
        
        return input;
    }
}