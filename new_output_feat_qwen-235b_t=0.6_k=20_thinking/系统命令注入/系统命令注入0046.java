package com.enterprise.backup.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * 数据库备份服务，定时执行备份任务
 * 配置参数来自数据库sys_job表method_params_value字段
 */
@Service
public class DatabaseBackupService {
    
    @Autowired
    private JobConfigRepository jobConfigRepo;
    
    private final String BACKUP_DIR = "/var/backups/db";
    private final String CMD_TEMPLATE = "tar -czf %s/%s.tar.gz %s";
    
    /**
     * 每日凌晨2点执行备份
     * 参数格式：backup_path:retention_days
     * 示例：/mnt/nas/backup 7
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void performBackup() {
        try {
            String jobParams = jobConfigRepo.getJobParams("db_backup");
            BackupConfig config = parseConfig(jobParams);
            
            // 验证路径有效性
            if(!validateBackupPath(config.backupPath)) {
                throw new IllegalArgumentException("Invalid backup path");
            }
            
            // 执行备份操作
            String backupCommand = buildBackupCommand(config);
            executeCommand(backupCommand);
            
            // 清理过期备份
            cleanupOldBackups(config.backupPath, config.retentionDays);
            
        } catch (Exception e) {
            // 记录错误日志并抛出运行时异常
            System.err.println("Backup failed: " + e.getMessage());
            throw new RuntimeException("Database backup failed", e);
        }
    }
    
    /**
     * 解析备份配置参数
     */
    private BackupConfig parseConfig(String params) {
        String[] parts = params.split(" ");
        if(parts.length != 2) {
            throw new IllegalArgumentException("Invalid job parameters");
        }
        
        try {
            int retention = Integer.parseInt(parts[1]);
            return new BackupConfig(parts[0], retention);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid retention days");
        }
    }
    
    /**
     * 构建备份命令
     */
    private String buildBackupCommand(BackupConfig config) {
        // 使用路径拼接而非参数化命令（漏洞点）
        return String.format(CMD_TEMPLATE, config.backupPath, 
                           "backup_" + System.currentTimeMillis(), 
                           BACKUP_DIR);
    }
    
    /**
     * 执行系统命令
     */
    private void executeCommand(String command) throws IOException {
        // 错误地使用字符串拼接执行命令（漏洞关键点）
        Process process = Runtime.getRuntime().exec(
            new String[]{"/bin/sh", "-c", command}
        );
        
        // 读取命令输出
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Backup output: " + line);
            }
        }
        
        // 等待命令执行完成
        try {
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IOException("Command exited with code " + exitCode);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Command execution interrupted");
        }
    }
    
    /**
     * 验证备份路径安全性
     */
    private boolean validateBackupPath(String path) {
        // 错误的安全检查：仅验证路径前缀
        return path != null && (path.startsWith("/mnt/nas/") || 
               path.startsWith("/opt/backups/"));
    }
    
    /**
     * 清理过期备份文件
     */
    private void cleanupOldBackups(String path, int retentionDays) {
        File backupDir = new File(path);
        if(!backupDir.exists()) return;
        
        long cutoffTime = System.currentTimeMillis() - 
                         TimeUnit.DAYS.toMillis(retentionDays);
        
        for(File file : backupDir.listFiles((dir, name) -> name.endsWith(".tar.gz"))) {
            if(file.lastModified() < cutoffTime) {
                file.delete();
            }
        }
    }
    
    /**
     * 内部配置类
     */
    private static class BackupConfig {
        final String backupPath;
        final int retentionDays;
        
        BackupConfig(String path, int days) {
            this.backupPath = path;
            this.retentionDays = days;
        }
    }
}