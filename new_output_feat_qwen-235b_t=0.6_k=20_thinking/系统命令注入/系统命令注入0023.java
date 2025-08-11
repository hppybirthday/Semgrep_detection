package com.gamestudio.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class GameTaskExecutor {
    private static final Logger LOGGER = Logger.getLogger("GameTaskExecutor");
    private final DbUtil dbUtil;

    public GameTaskExecutor() {
        this.dbUtil = new DbUtil();
    }

    public String executeBackupTask(String dbName, String user, String password) {
        try {
            // 验证参数合法性
            if (!InputSanitizer.isValidDatabaseName(dbName) || 
                !InputSanitizer.isValidCredentials(user, password)) {
                return "Invalid input parameters";
            }

            // 执行数据库备份操作
            ProcessResult result = dbUtil.backupDatabase(dbName, user, password);
            
            // 记录操作日志
            if (result.exitCode == 0) {
                LOGGER.info("Backup successful for database: " + dbName);
                return "Backup completed: " + result.output;
            } else {
                LOGGER.severe("Backup failed for database: " + dbName + ", Error: " + result.output);
                return "Backup failed: " + result.output;
            }
        } catch (Exception e) {
            LOGGER.severe("Unexpected error during backup: " + e.getMessage());
            return "System error occurred";
        }
    }

    private static class ProcessResult {
        int exitCode;
        String output;
    }

    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Usage: java GameTaskExecutor <command> <dbName> <user> <password>");
            return;
        }

        GameTaskExecutor executor = new GameTaskExecutor();
        
        // 模拟Web参数解析
        String cmd = args[0];
        String dbName = args[1];
        String user = args[2];
        String password = args[3];
        
        if ("backup".equals(cmd)) {
            String result = executor.executeBackupTask(dbName, user, password);
            System.out.println(result);
        }
    }
}

class DbUtil {
    public ProcessResult backupDatabase(String databaseName, String user, String password) {
        try {
            // 构造系统命令（存在漏洞点）
            String[] cmd = {
                "/bin/sh",
                "-c",
                "mysqldump -u " + user + " -p" + password + " " + databaseName
            };
            
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Process process = pb.start();
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            ProcessResult result = new ProcessResult();
            result.exitCode = process.waitFor();
            result.output = output.toString();
            return result;
            
        } catch (Exception e) {
            throw new RuntimeException("Database operation failed", e);
        }
    }
}

class InputSanitizer {
    // 表面验证但存在逻辑漏洞
    public static boolean isValidDatabaseName(String name) {
        // 误以为只允许字母数字
        return name != null && name.matches("[a-zA-Z0-9_]+@internal");
    }
    
    public static boolean isValidCredentials(String cred) {
        // 错误的过滤实现
        return cred != null && !cred.contains(";") && !cred.contains("`");
    }
}