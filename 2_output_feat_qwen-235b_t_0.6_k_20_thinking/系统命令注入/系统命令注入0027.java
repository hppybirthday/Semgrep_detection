package com.cloudnative.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.apache.commons.lang3.StringUtils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * 定时任务处理器
 * 执行系统备份操作
 */
@Component
public class BackupScheduler {
    private final BackupConfig backupConfig = new BackupConfig();

    /**
     * 每日02:00执行备份任务
     * 使用配置的备份路径进行文件归档
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void executeBackup() {
        String backupPath = backupConfig.getBackupPath();
        if (StringUtils.isBlank(backupPath)) {
            // 默认路径校验
            backupPath = "/var/backups";
        }
        
        try {
            // 构造备份命令
            String command = String.format("tar -czf %s/backup_%s.tar.gz -C %s .", 
                backupPath, TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()), backupPath);
            
            // 执行系统命令
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            // 读取执行输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                // 记录备份日志
                System.out.println("[Backup] " + line);
            }
            
        } catch (IOException e) {
            System.err.println("Backup failed: " + e.getMessage());
        }
    }
}

/**
 * 备份配置管理类
 * 提供动态配置加载功能
 */
class BackupConfig {
    private String backupPath = System.getenv("BACKUP_PATH");

    /**
     * 获取备份路径
     * 从环境变量加载默认值
     */
    public String getBackupPath() {
        if (StringUtils.isBlank(backupPath)) {
            // 环境变量未配置时使用默认路径
            return "/var/backups";
        }
        
        // 路径格式标准化处理
        String normalizedPath = backupPath.trim();
        if (normalizedPath.contains("..") || normalizedPath.contains("~")) {
            // 阻止路径穿越攻击
            throw new SecurityException("Invalid path characters");
        }
        
        return normalizedPath;
    }
}