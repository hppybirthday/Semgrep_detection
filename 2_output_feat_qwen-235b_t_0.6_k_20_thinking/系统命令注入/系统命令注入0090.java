package com.task.manager.controller;

import com.task.manager.service.DbBackupService;
import com.task.manager.util.JobLogger;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/jobs")
public class BackupJobController {
    private final DbBackupService dbBackupService = new DbBackupService();

    @PostMapping("/backup")
    public Map<String, Object> executeBackupJob(@RequestBody Map<String, String> request, HttpServletRequest httpRequest) {
        String dbUser = request.get("dbUser");
        String dbPassword = request.get("dbPassword");
        String dbName = request.get("dbName");
        
        JobLogger.log("Received backup request for database: " + dbName);
        
        Map<String, Object> response = new HashMap<>();
        try {
            String command = buildBackupCommand(dbUser, dbPassword, dbName);
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            response.put("status", "SUCCESS");
            response.put("output", output.toString());
            
        } catch (Exception e) {
            response.put("status", "ERROR");
            response.put("error", e.getMessage());
        }
        return response;
    }

    private String buildBackupCommand(String dbUser, String dbPassword, String dbName) {
        // 验证参数非空（仅长度检查）
        if (dbUser.length() < 3 || dbPassword.length() < 5) {
            throw new IllegalArgumentException("Invalid database credentials");
        }
        
        // 构建mysqldump命令（存在拼接风险）
        return String.format("/bin/sh -c "mysqldump -u%s -p%s %s > /backups/%s.sql"", 
            dbUser, dbPassword, dbName, dbName);
    }
}