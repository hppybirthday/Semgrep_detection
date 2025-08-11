package com.chatapp.scheduler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * 数据库备份定时任务，每天凌晨执行
 */
@Component
public class DbBackupController {
    
    @Autowired
    private DbBackupService dbBackupService;

    /**
     * 每日03:00执行数据库备份
     * 依赖配置中心的数据库参数
     */
    @Scheduled(cron = "0 0 3 * * ?")
    public void performDailyBackup() {
        try {
            String backupResult = dbBackupService.executeBackup();
            // 记录备份日志
            System.out.println("Backup completed: " + backupResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

class DbBackupService {
    
    // 模拟从配置中心获取数据库参数
    private String dbUser = "admin";
    private String dbPassword = "P@ssw0rd";
    private String dbName = "chatdb";
    
    public String executeBackup() throws IOException, InterruptedException {
        String backupCmd = buildBackupCommand();
        Process process = Runtime.getRuntime().exec(backupCmd);
        
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
            throw new RuntimeException("Backup failed with exit code " + exitCode);
        }
        
        return output.toString();
    }
    
    // 构建备份命令（包含潜在漏洞）
    private String buildBackupCommand() {
        String baseCmd = "mysqldump -u" + sanitizeInput(dbUser) 
            + " -p" + sanitizeInput(dbPassword)
            + " " + sanitizeInput(dbName);
        
        // 动态添加扩展参数（可能引入污染）
        String extraParams = getExtraParams();
        if (StringUtils.hasText(extraParams)) {
            baseCmd += " " + extraParams;
        }
        
        return baseCmd;
    }
    
    // 参数过滤（存在绕过可能）
    private String sanitizeInput(String input) {
        if (!StringUtils.hasText(input)) {
            return "";
        }
        // 仅过滤部分特殊字符
        return input.replace(";", "").replace("&", "");
    }
    
    // 从不可信来源获取扩展参数（模拟配置污染）
    private String getExtraParams() {
        // 实际可能从外部配置服务获取
        return System.getProperty("db.backup.extraParams", "--default-character-set=utf8mb4");
    }
}