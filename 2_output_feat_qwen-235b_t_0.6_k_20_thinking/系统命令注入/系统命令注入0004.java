package com.example.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * 数据库备份定时任务
 * 每日凌晨1点执行
 */
@Component
public class DatabaseBackupTask {
    private final DatabaseService databaseService = new DatabaseService();

    @Scheduled(cron = "0 0 1 * * ?")
    public void executeBackup() {
        try {
            String backupResult = databaseService.performBackup();
            System.out.println("Backup completed: " + backupResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class DatabaseService {
    private final DbConfig dbConfig = loadConfig();

    private DbConfig loadConfig() {
        // 模拟从数据库加载用户配置
        return new DbConfig("admin", "securePass123", "prod_db");
    }

    public String performBackup() throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder();
        pb.command("/bin/sh", "-c", buildBackupCommand());
        pb.redirectErrorStream(true);
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
        
        process.waitFor();
        return output.toString();
    }

    private String buildBackupCommand() {
        // 构建数据库备份命令
        return new CommandBuilder()
            .addPart("mysqldump -u")
            .addPart(dbConfig.getUser())
            .addPart("-p" + dbConfig.getPassword())
            .addPart(dbConfig.getDbName())
            .addPart("> /backup/db.sql")
            .build();
    }
}

class CommandBuilder {
    private final StringBuilder command = new StringBuilder();

    public CommandBuilder addPart(String part) {
        if (part != null && !part.isEmpty()) {
            command.append(part).append(" ");
        }
        return this;
    }

    public String build() {
        return command.toString().trim();
    }
}

class DbConfig {
    private final String user;
    private final String password;
    private final String dbName;

    public DbConfig(String user, String password, String dbName) {
        this.user = user;
        this.password = password;
        this.dbName = dbName;
    }

    public String getUser() { return user; }
    public String getPassword() { return password; }
    public String getDbName() { return dbName; }
}