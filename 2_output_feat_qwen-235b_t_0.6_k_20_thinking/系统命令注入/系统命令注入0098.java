package com.example.dbbackup.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
public class DatabaseBackupController {

    @GetMapping("/backup")
    public String backupDatabase(@RequestParam String dbName) throws IOException {
        validateInput(dbName);
        String command = buildCommand(dbName);
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        Process process = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line).append("\n");
        }
        return result.toString();
    }

    private void validateInput(String dbName) {
        if (dbName == null || dbName.isEmpty()) {
            throw new IllegalArgumentException("Database name cannot be empty");
        }
        if (dbName.length() > 30) {
            throw new IllegalArgumentException("Database name exceeds maximum length");
        }
    }

    private String buildCommand(String dbName) {
        // 构建完整数据库备份命令
        return "mysqldump -u admin -pPassword123 --set-charset=utf8 " + dbName;
    }
}