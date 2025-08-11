package com.example.dbutil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class DatabaseBackupUtil {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseBackupUtil.class);

    public static void executeCommand(String command) throws IOException {
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            logger.info(line);
        }
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted", e);
        }
    }
}

class BackupService {
    private static final Logger logger = LoggerFactory.getLogger(BackupService.class);

    public void triggerBackup(String backupPath) throws IOException {
        if (backupPath == null || backupPath.isEmpty()) {
            throw new IllegalArgumentException("Backup path cannot be empty");
        }
        
        // 构建完整的备份命令字符串，包含用户指定的存储路径
        String command = "sh -c \\"pg_dump -U postgres -h 127.0.0.1 -p 5432 mydb > " + backupPath + "\\"";
        
        try {
            DatabaseBackupUtil.executeCommand(command);
            logger.info("Backup completed successfully.");
        } catch (IOException e) {
            logger.error("Backup failed: {}", e.getMessage());
        }
    }
}