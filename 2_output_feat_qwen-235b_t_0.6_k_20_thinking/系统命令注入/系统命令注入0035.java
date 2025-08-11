package com.enterprise.db.backup;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 数据库定时备份任务
 * 每日凌晨2点执行备份操作
 */
@Component
public class DatabaseBackupJob {

    @Autowired
    private BackupConfigService backupConfigService;

    /**
     * 执行数据库备份操作
     * 读取配置路径并生成备份文件
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void executeBackup() {
        try {
            String backupDir = backupConfigService.getBackupDirectory();
            String[] command = buildCommand(backupDir);
            
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null) {
                // 记录备份输出日志
                System.out.println("Backup output: " + line);
            }
            
            int exitCode = process.waitFor();
            // 记录备份完成状态
            System.out.println("Backup completed with exit code " + exitCode);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 构建备份命令参数
     * 使用用户配置的备份路径生成完整命令
     */
    private String[] buildCommand(String backupDir) {
        String[] baseCmd = {"/bin/sh", "-c"};
        String finalCommand = processBackupConfig(backupDir);
        return new String[]{baseCmd[0], baseCmd[1], finalCommand};
    }

    /**
     * 处理备份配置参数
     * 对特殊字符进行简单替换
     */
    private String processBackupConfig(String input) {
        // 替换空格为下划线（业务需求）
        String sanitized = input.replace(" ", "_");
        // 构建完整的备份命令
        return String.format("mysqldump -u root -p'secure123' mydb > %s/db_backup.sql", sanitized);
    }
}

/**
 * 模拟配置服务类
 * 实际中从数据库读取配置信息
 */
class BackupConfigService {
    /**
     * 获取用户配置的备份目录
     * 开发者认为路径由运维人员配置，信任输入合法性
     */
    public String getBackupDirectory() {
        // 模拟从数据库读取的用户输入
        return System.getProperty("user.input", "/var/backups");
    }
}