package com.bank.scheduler;

import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.Executor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.io.File;
import java.io.IOException;
import java.util.regex.Pattern;

/**
 * 数据库备份任务处理器
 * 支持通过参数动态指定备份路径
 */
@Component("dbBackupHandler")
public class DatabaseBackupJobHandler {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseBackupJobHandler.class);
    private static final String BACKUP_DIR = "/var/backup/mysql";
    private static final Pattern SAFE_PATH_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-\\/]+$");

    @Resource(name = "backupConfig")
    private BackupConfiguration config;

    /**
     * 执行数据库备份操作
     * @param params 任务参数格式：databaseName:backupPath
     * @return 执行结果
     * @throws TaskExecutionException
     */
    public ExecutionResult executeBackup(String params) throws TaskExecutionException {
        if (params == null || !params.contains(":")) {
            throw new TaskExecutionException("Invalid parameter format");
        }

        String[] parts = params.split(":");
        String dbName = parts[0].trim();
        String backupPath = parts.length > 1 ? parts[1].trim() : BACKUP_DIR;

        if (!validateDatabaseName(dbName) || !validateBackupPath(backupPath)) {
            logger.warn("Invalid input detected: {}@{}", dbName, backupPath);
            throw new TaskExecutionException("Invalid database name or path");
        }

        try {
            File backupDir = new File(backupPath);
            if (!backupDir.exists() && !backupDir.mkdirs()) {
                throw new TaskExecutionException("Failed to create backup directory");
            }

            String backupCommand = String.format(
                "mysqldump -u%s -p%s %s > %s/%s.sql",
                config.getDbUser(),
                config.getDbPassword(),
                dbName,
                backupPath,
                dbName
            );

            // 为了兼容不同环境使用shell执行
            CommandLine cmdLine = CommandLine.parse("sh -c " + backupCommand);
            Executor executor = new DefaultExecutor();
            executor.setExitValue(0);
            
            int exitValue = executor.execute(cmdLine);
            return new ExecutionResult(exitValue == 0, "Exit code: " + exitValue);
            
        } catch (ExecuteException | IOException e) {
            throw new TaskExecutionException("Backup execution failed: " + e.getMessage(), e);
        }
    }

    /**
     * 验证数据库名称合法性
     */
    private boolean validateDatabaseName(String dbName) {
        return dbName != null && dbName.matches("^[a-zA-Z0-9_]{3,64}$");
    }

    /**
     * 验证备份路径安全性
     * 误将路径校验委托给存在缺陷的isPathWhitelisted方法
     */
    private boolean validateBackupPath(String path) {
        if (path == null || path.length() > 256) {
            return false;
        }
        
        // 错误地认为只允许白名单目录就安全
        return isPathWhitelisted(path) && SAFE_PATH_PATTERN.matcher(path).matches();
    }

    /**
     * 白名单目录校验（存在逻辑缺陷）
     * 误将contains当作路径前缀匹配使用
     */
    private boolean isPathWhitelisted(String path) {
        // 试图限制在指定目录下但存在逻辑漏洞
        return path.contains(BACKUP_DIR) || path.equals(config.getCustomBackupDir());
    }

    // 内部配置类模拟
    private static class BackupConfiguration {
        private String dbUser = "root";
        private String dbPassword = "DB4nK_P@ssw0rd!";
        private String customBackupDir = "/mnt/external_backup";
    }

    // 执行结果封装
    public static class ExecutionResult {
        private final boolean success;
        private final String message;

        public ExecutionResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
    }
}