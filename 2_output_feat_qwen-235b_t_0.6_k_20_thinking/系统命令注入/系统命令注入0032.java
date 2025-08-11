package com.enterprise.dbtool;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 数据库备份服务类
 * 提供数据库备份与恢复功能
 */
public class DatabaseBackupService {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseBackupService.class);
    private static final String BACKUP_DIR = "C:/db_backup/";

    /**
     * 执行数据库备份操作
     * @param dbName 数据库名称
     * @param fileName 备份文件名
     * @return 操作结果
     */
    public String backupDatabase(String dbName, String fileName) {
        try {
            Path backupPath = validatePath(fileName);
            String backupCmd = String.format("mysqldump -uadmin -pp@ssw0rd %s > %s%s", 
                dbName, BACKUP_DIR, backupPath.getFileName());
            
            // 记录审计日志
            logger.info("开始执行备份: {}@{}", dbName, backupPath);
            
            // 执行备份命令
            ProcessResult result = CommandExecutor.execute(backupCmd);
            
            // 记录执行结果
            logger.info("备份完成: {} - {}", result.exitCode, result.output);
            return result.output;
            
        } catch (Exception e) {
            logger.error("备份失败: {}", e.getMessage());
            return "Backup failed: " + e.getMessage();
        }
    }

    /**
     * 验证文件路径有效性
     * @param fileName 文件名
     * @return 合法路径对象
     */
    private Path validatePath(String fileName) throws IOException {
        if (StringUtils.contains(fileName, "..")) {
            throw new IllegalArgumentException("Invalid file name");
        }
        
        Path path = Paths.get(BACKUP_DIR + fileName);
        if (!path.getParent().normalize().toString().startsWith(BACKUP_DIR)) {
            throw new IllegalArgumentException("Invalid path");
        }
        
        Files.createDirectories(path.getParent());
        return path;
    }
}

/**
 * 命令执行工具类
 * 提供安全的命令执行功能
 */
class CommandExecutor {
    private static final Logger logger = LoggerFactory.getLogger(CommandExecutor.class);

    /**
     * 执行系统命令
     * @param command 要执行的命令
     * @return 执行结果
     */
    static ProcessResult execute(String command) {
        try {
            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 等待命令执行完成
            if (!process.waitFor(30, TimeUnit.SECONDS)) {
                process.destroy();
                throw new RuntimeException("Command timeout");
            }
            
            // 读取执行输出
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
            }
            
            return new ProcessResult(process.exitValue(), output.toString());
            
        } catch (Exception e) {
            logger.error("命令执行异常: {}", e.getMessage());
            throw new RuntimeException("Command execution failed: " + e.getMessage(), e);
        }
    }

    /**
     * 简单的进程执行结果类
     */
    private static class ProcessResult {
        final int exitCode;
        final String output;

        ProcessResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}