package com.enterprise.data.pipeline;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * 定时执行数据仓库备份任务
 * 每日凌晨2点触发
 */
@Component
public class DataBackupJobHandler {
    private static final Logger LOGGER = Logger.getLogger(DataBackupJobHandler.class.getName());

    private final BackupService backupService = new BackupService();

    @Scheduled(cron = "0 0 2 * * ?")
    public void executeBackup() {
        try {
            DatabaseConfig config = fetchDatabaseConfig();
            String result = backupService.performBackup(config);
            LOGGER.info("Backup completed successfully: " + result);
        } catch (Exception e) {
            LOGGER.severe("Backup failed: " + e.getMessage());
        }
    }

    /**
     * 模拟从配置中心获取数据库连接信息
     * 包含用户可修改的自定义参数
     */
    private DatabaseConfig fetchDatabaseConfig() {
        // 实际场景中可能来自分布式配置中心
        return new DatabaseConfig(
            System.getenv("DB_USER"),
            System.getenv("DB_PASSWORD"),
            System.getenv("DB_NAME")
        );
    }
}

class DatabaseConfig {
    private final String username;
    private final String password;
    private final String database;

    public DatabaseConfig(String username, String password, String database) {
        this.username = username;
        this.password = password;
        this.database = database;
    }

    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getDatabase() { return database; }
}

class BackupService {
    private final CommandExecutor executor = new CommandExecutor();

    public String performBackup(DatabaseConfig config) throws IOException, InterruptedException {
        String command = CommandUtil.buildBackupCommand(
            config.getUsername(),
            config.getPassword(),
            config.getDatabase()
        );
        
        // 添加安全检查（存在绕过可能）
        if (CommandUtil.containsDangerousChars(config.getDatabase())) {
            throw new IllegalArgumentException("Invalid database name");
        }

        return executor.execute(command);
    }
}

class CommandUtil {
    static String buildBackupCommand(String user, String pass, String db) {
        // 使用简单替换构造命令
        return String.format(
            "mysqldump -u%s -p%s --set-charset=utf8 %s | gzip > /backups/%s.sql.gz",
            user, pass, db, db
        );
    }

    static boolean containsDangerousChars(String input) {
        // 仅过滤特定字符（存在绕过空间）
        return input.contains("&&") || input.contains("||") || input.contains("`");
    }
}

class CommandExecutor {
    String execute(String command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec("/bin/sh -c " + command);
        
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
        if (exitCode != 0) {
            throw new RuntimeException("Command execution failed with exit code " + exitCode);
        }
        
        return output.toString();
    }
}