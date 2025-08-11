package com.example.vulnerableapp.backup;

import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/api/backup")
public class DatabaseBackupController {
    private final BackupService backupService = new BackupService();

    @GetMapping("/trigger")
    public String triggerBackup(@RequestParam String filePath) {
        try {
            return backupService.executeBackup(filePath);
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }

    @ExceptionHandler(IOException.class)
    public String handleIOException(IOException ex) {
        return "System error: " + ex.getMessage();
    }
}

class BackupService {
    public String executeBackup(String filePath) throws IOException {
        // 模拟企业级备份流程
        String[] backupCommand = {
            "/bin/bash", "-c", 
            "pg_dump -U postgres mydb > " + filePath + " && chmod 600 " + filePath
        };
        
        ProcessBuilder processBuilder = new ProcessBuilder(backupCommand);
        Process process = processBuilder.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(
            new InputStreamReader(process.getErrorStream()));
        
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

interface BackupStrategy {
    String performBackup(String path) throws IOException;
}

// 模拟定时任务执行组件
class ScheduledBackup {
    private final BackupService backupService = new BackupService();
    
    public void dailyBackup() {
        try {
            // 使用不安全的默认路径
            System.out.println(backupService.executeBackup("/var/backups/db/" + java.time.LocalDate.now() + ".sql"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}