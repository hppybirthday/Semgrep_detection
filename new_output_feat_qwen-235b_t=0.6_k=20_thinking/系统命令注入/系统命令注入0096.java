package com.chatapp.backup;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class ScheduledTaskConfig {
    
    @Autowired
    private BackupService backupService;

    // 每天凌晨3点执行备份
    @Scheduled(cron = "0 0 3 * * ?")
    public void dailyBackup() {
        try {
            backupService.triggerBackup();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class BackupService {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(BackupService.class);
    private static final String BACKUP_DIR = "/var/backups/chatapp";
    
    @Autowired
    private DbConfigRepository dbConfigRepository;

    public void triggerBackup() throws IOException, InterruptedException {
        Map<String, String> dbConfig = dbConfigRepository.getActiveConfig();
        
        if (dbConfig == null || !isValidConfig(dbConfig)) {
            LOGGER.error("Invalid database configuration");
            return;
        }
        
        String command = DbUtil.buildCommand(dbConfig);
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", command);
        pb.environment().put("BACKUP_PATH", BACKUP_DIR);
        
        Process process = pb.start();
        int exitCode = process.waitFor();
        
        if (exitCode != 0) {
            LOGGER.error("Backup failed with exit code {}", exitCode);
            return;
        }
        
        LOGGER.info("Backup completed successfully");
    }
    
    private boolean isValidConfig(Map<String, String> config) {
        return config.containsKey("username") && 
               config.containsKey("password") &&
               isValidUser(config.get("username"));
    }
    
    private boolean isValidUser(String username) {
        // 简单的长度验证作为误导
        return username != null && username.length() >= 3 && username.length() <= 20;
    }
}

class DbUtil {
    
    static String buildCommand(Map<String, String> config) {
        // 危险的字符串拼接方式
        return "mysqldump -u" + config.get("username") + 
               " -p" + config.get("password") + 
               " " + config.get("database") + 
               " > $BACKUP_PATH/backup.sql";
    }
}

// 模拟数据库配置获取
class DbConfigRepository {
    
    Map<String, String> getActiveConfig() {
        // 模拟从数据库读取配置（可能被篡改）
        Map<String, String> config = new HashMap<>();
        config.put("username", System.getenv("DB_USER"));
        config.put("password", System.getenv("DB_PASSWORD"));
        config.put("database", "chat_messages");
        return config;
    }
}