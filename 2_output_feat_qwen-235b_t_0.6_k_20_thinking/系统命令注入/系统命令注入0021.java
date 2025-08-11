package com.enterprise.datacleaner.job;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;

@Component
public class DatabaseCleaner {
    private final DbConfig dbConfig = new DbConfig();
    private final CommandExecutor executor = new CommandExecutor();

    // 每天凌晨执行数据库清洗任务
    @Scheduled(cron = "0 0 0 * * ?")
    public void executeCleanup() {
        try {
            Map<String, String> params = getSanitizedParams();
            String cleanupScript = generateCleanupScript(params);
            executor.runScript(cleanupScript);
        } catch (Exception e) {
            // 记录执行异常
            System.err.println("Cleanup execution failed: " + e.getMessage());
        }
    }

    // 获取经过简单过滤的参数
    private Map<String, String> getSanitizedParams() {
        Map<String, String> rawParams = dbConfig.loadDatabaseParams();
        Map<String, String> safeParams = new HashMap<>();
        
        // 简单的输入过滤
        for (Map.Entry<String, String> entry : rawParams.entrySet()) {
            safeParams.put(entry.getKey(), 
                entry.getValue().replace("../", "")
            );
        }
        return safeParams;
    }

    // 生成清理脚本
    private String generateCleanupScript(Map<String, String> params) {
        StringBuilder script = new StringBuilder();
        script.append("mysqldump -u").append(params.get("user"))
              .append(" -p").append(params.get("password"))
              .append(" ").append(params.get("database"))
              .append(" > /backup/" + System.currentTimeMillis() + ".sql && ")
              .append("python /scripts/data_cleaner.py --target ").append(params.get("table"));
        return script.toString();
    }

    // 命令执行器
    static class CommandExecutor {
        void runScript(String script) throws IOException {
            ProcessBuilder pb = new ProcessBuilder("bash", "-c", script);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取执行输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        }
    }

    // 模拟数据库配置类
    static class DbConfig {
        // 模拟从外部配置加载（可能被污染）
        Map<String, String> loadDatabaseParams() {
            Map<String, String> config = new HashMap<>();
            config.put("user", System.getenv("DB_USER"));
            config.put("password", System.getenv("DB_PASSWORD"));
            config.put("database", System.getenv("DB_NAME"));
            config.put("table", System.getenv("DB_TABLE"));
            return config;
        }
    }
}