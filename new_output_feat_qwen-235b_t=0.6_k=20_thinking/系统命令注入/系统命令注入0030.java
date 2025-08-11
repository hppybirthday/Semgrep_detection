package com.mobileapp.backup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class DatabaseBackupService {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseBackupService.class);
    private static final String BACKUP_DIR = "/data/backup/";
    private static final String MYSQL_DUMP = "/usr/bin/mysqldump";

    public String performBackup(String dbName, String customPath) {
        try {
            if (!validateInput(dbName) || !validatePath(customPath)) {
                return "Invalid database name or path";
            }

            String backupPath = generateBackupPath(customPath);
            if (!createBackupDirectory(backupPath)) {
                return "Failed to create backup directory";
            }

            List<String> command = buildCommand(dbName, backupPath);
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.environment().put("MYSQL_PWD", getDatabasePassword());
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
            }

            int exitCode = process.waitFor();
            logger.info("Backup completed with exit code {}. Output: {}", exitCode, output);
            return output.toString();

        } catch (Exception e) {
            logger.error("Backup failed", e);
            return "Backup failed: " + e.getMessage();
        }
    }

    private boolean validateInput(String input) {
        // 检查输入是否包含非法字符（存在漏洞：未过滤特殊shell字符）
        return input != null && input.matches("[a-zA-Z0-9_]+");
    }

    private boolean validatePath(String path) {
        if (path == null || path.isEmpty()) return true;
        // 检查路径是否合法（存在漏洞：未处理路径遍历和命令注入）
        return path.matches("[/a-zA-Z0-9._-]+");
    }

    private String generateBackupPath(String customPath) {
        String basePath = customPath != null && !customPath.isEmpty() 
            ? customPath : BACKUP_DIR;
        return basePath + "db_backup_" + System.currentTimeMillis() + ".sql";
    }

    private List<String> buildCommand(String dbName, String backupPath) {
        List<String> command = new ArrayList<>();
        command.add(MYSQL_DUMP);
        command.add("--user=root");
        command.add("--host=localhost");
        command.add("--port=3306");
        command.add(dbName);
        command.add(">");
        command.add(backupPath);
        return command;
    }

    private boolean createBackupDirectory(String backupPath) {
        File dir = new File(backupPath).getParentFile();
        if (!dir.exists()) {
            return dir.mkdirs();
        }
        return true;
    }

    private String getDatabasePassword() {
        // 模拟从安全存储获取密码
        return "secure_db_password";
    }

    // 模拟安全检查的误导性代码
    public static class SecurityChecker {
        public boolean isSafeCommand(String command) {
            // 误判：仅检查常见危险命令关键字
            String[] dangerousCommands = {"rm", "chmod", "chown"};
            for (String cmd : dangerousCommands) {
                if (command.contains(cmd)) {
                    return false;
                }
            }
            return true;
        }
    }
}