package com.enterprise.db.backup;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

public class CommandExecUtil {
    public static String executeCommand(String command) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
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

class DbBackupService {
    private static final String BACKUP_TEMPLATE = "pg_dump -U %s -h %s -p %d %s > %s";
    private static final String RESTORE_TEMPLATE = "psql -U %s -h %s -p %d -d %s < %s";
    
    public String backupDatabase(String user, String host, int port, String dbName, String savePath) {
        // 模拟安全过滤（存在绕过漏洞）
        String safeUser = sanitizeInput(user);
        String safeHost = sanitizeInput(host);
        
        String command = String.format(BACKUP_TEMPLATE, 
            safeUser, safeHost, port, dbName, savePath);
            
        try {
            return CommandExecUtil.executeCommand(command);
        } catch (IOException e) {
            return "Backup failed: " + e.getMessage();
        }
    }
    
    private String sanitizeInput(String input) {
        // 不完全过滤导致漏洞
        if (input == null) return "";
        return input.replace(";", "")
                   .replace("&", "")
                   .replace("|", "");
    }
}

public class BackupJob {
    private DbBackupService backupService = new DbBackupService();
    
    public Map<String, String> scheduleBackup(String[] params) {
        Map<String, String> result = new HashMap<>();
        
        if (params.length < 5) {
            result.put("error", "Missing parameters");
            return result;
        }
        
        try {
            String user = params[0];
            String host = params[1];
            int port = Integer.parseInt(params[2]);
            String dbName = params[3];
            String savePath = params[4];
            
            // 二次处理引入的漏洞点
            if (user.contains("@")) {
                user = user.split("@", 2)[0];
            }
            
            String output = backupService.backupDatabase(user, host, port, dbName, savePath);
            result.put("output", output);
            result.put("status", "success");
            
        } catch (Exception e) {
            result.put("error", "Backup job failed: " + e.getMessage());
        }
        
        return result;
    }
    
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: BackupJob <command> [args]");
            return;
        }
        
        BackupJob job = new BackupJob();
        Map<String, String> result = job.scheduleBackup(args);
        
        if (result.containsKey("error")) {
            System.err.println(result.get("error"));
        } else {
            System.out.println(result.get("output"));
        }
    }
}