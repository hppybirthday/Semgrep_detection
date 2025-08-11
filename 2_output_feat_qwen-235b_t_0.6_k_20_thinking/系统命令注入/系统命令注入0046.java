package com.example.scheduler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

public class ConfigurableTask {
    private final String dbUser;
    private final String dbPassword;
    private final String dbName;
    private final String backupPath;

    public ConfigurableTask(String dbUser, String dbPassword, String dbName, String backupPath) {
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        this.dbName = dbName;
        this.backupPath = backupPath;
    }

    public String executeBackup(String s) {
        if (!validateInput(s)) {
            return "Invalid input format";
        }
        
        String command = DbUtil.buildBackupCommand(
            dbUser, 
            dbPassword, 
            dbName, 
            backupPath + "\\\\" + s
        );
        
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getErrorStream())
            );
            
            String line;
            StringBuilder output = new StringBuilder();
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            process.waitFor(10, TimeUnit.SECONDS);
            return output.toString();
            
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Backup execution failed: " + e.getMessage();
        }
    }

    private boolean validateInput(String input) {
        // 校验输入长度和基本格式（示例校验规则）
        return input != null && input.length() <= 128;
    }
}

final class DbUtil {
    static String buildBackupCommand(String user, String password, String database, String path) {
        // 构建Windows平台下的备份命令（示例格式）
        // 注意：未对用户输入进行特殊字符转义
        return String.format("mysqldump -u%s -p%s %s > %s.sql", 
            user, password, database, path);
    }
}