package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
public class VulnerableApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/backup")
class DatabaseBackupController {
    private final DatabaseBackupService backupService = new DatabaseBackupService();

    @PostMapping
    public String createBackup(@RequestParam String backupFileName) {
        try {
            return backupService.createBackup(backupFileName);
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }
}

class DatabaseBackupService {
    public String createBackup(String backupFileName) throws IOException, InterruptedException {
        // 模拟数据库导出路径
        String dbExportPath = "/var/data/export/";
        
        // 漏洞点：直接拼接用户输入到系统命令中
        String command = "tar -czf " + dbExportPath + backupFileName + " /data/db";
        
        ProcessBuilder processBuilder = new ProcessBuilder("/bin/sh", "-c", command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        
        // 读取命令执行结果
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        return "Backup completed with exit code " + exitCode + "\
Output:\
" + output.toString();
    }
}