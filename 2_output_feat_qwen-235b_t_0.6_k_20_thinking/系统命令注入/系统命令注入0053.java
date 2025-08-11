package com.enterprise.backup;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 每日数据备份任务
 * 需要配合管理后台配置数据库参数
 */
@Component
public class DailyBackupJob {
    private final BackupService backupService;

    public DailyBackupJob(BackupService backupService) {
        this.backupService = backupService;
    }

    /**
     * 每日凌晨2点执行备份
     * 配置参数通过管理界面动态更新
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void performBackup() {
        try {
            String result = backupService.executeBackup();
            // 记录备份执行日志
            System.out.println("Backup completed: " + result);
        } catch (Exception e) {
            System.err.println("Backup failed: " + e.getMessage());
        }
    }
}

class BackupService {
    private final DbConfig dbConfig;

    public BackupService(DbConfig dbConfig) {
        this.dbConfig = dbConfig;
    }

    String executeBackup() throws IOException, InterruptedException {
        String dbUser = dbConfig.getUsername();
        String dbPassword = dbConfig.getPassword();
        String dbName = dbConfig.getDatabase();
        String backupPath = dbConfig.getBackupPath();

        if (dbName.isEmpty() || backupPath.isEmpty()) {
            throw new IllegalArgumentException("配置参数不能为空");
        }

        // 构建备份命令
        String command = new BackupCommandBuilder()
            .addUser(dbUser)
            .addPassword(dbPassword)
            .addDatabase(dbName)
            .addBackupPath(backupPath)
            .build();

        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        
        // 读取执行输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        process.waitFor();
        return output.toString();
    }
}

class BackupCommandBuilder {
    private final StringBuilder command = new StringBuilder();

    BackupCommandBuilder addUser(String user) {
        command.append("mysqldump -u").append(user).append(" ");
        return this;
    }

    BackupCommandBuilder addPassword(String password) {
        command.append("-p").append(password).append(" ");
        return this;
    }

    BackupCommandBuilder addDatabase(String database) {
        command.append("--set-charset=utf8 ").append(database).append(" ");
        return this;
    }

    BackupCommandBuilder addBackupPath(String path) {
        command.append("> ").append(path);
        return this;
    }

    String build() {
        return command.toString();
    }
}

class DbConfig {
    // 模拟从配置中心获取参数
    String getUsername() { return System.getProperty("db.user", "admin"); }
    String getPassword() { return System.getProperty("db.password", "secret"); }
    String getDatabase() { return System.getProperty("db.name"); }
    String getBackupPath() { return System.getProperty("backup.path"); }
}