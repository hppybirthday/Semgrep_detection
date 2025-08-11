package com.example.dataprocess.cleaner;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 数据清洗任务处理器
 * 定时从外部数据源拉取数据并进行清洗
 */
@Component
public class DataCleanerTask {
    @Autowired
    private RestTemplate restTemplate;

    // 模拟从配置中心获取数据源地址
    private String dataSourceUrl = "http://config-center.example.com/api/data-source";

    // 定时任务：每天凌晨2点执行数据清洗
    @Scheduled(cron = "0 0 2 * * ?")
    public void performDataCleaning() {
        try {
            // 1. 获取数据源配置
            DataSourceConfig config = fetchDataSourceConfig();
            
            // 2. 验证数据源有效性
            if (!validateDataSource(config)) {
                logError("Invalid data source configuration");
                return;
            }
            
            // 3. 下载原始数据
            String rawData = downloadRawData(config.getSourceUrl());
            
            // 4. 执行数据清洗
            String cleanedData = cleanData(rawData);
            
            // 5. 存储清洗后数据
            storeCleanedData(cleanedData);
            
        } catch (Exception e) {
            logError("Data cleaning failed: " + e.getMessage());
        }
    }

    // 获取数据源配置
    private DataSourceConfig fetchDataSourceConfig() {
        return restTemplate.getForObject(dataSourceUrl, DataSourceConfig.class);
    }

    // 验证数据源合法性
    private boolean validateDataSource(DataSourceConfig config) {
        if (config == null || config.getSourceUrl() == null) {
            return false;
        }
        
        // 检查是否允许的协议类型
        if (!config.getSourceUrl().startsWith("http://") && 
            !config.getSourceUrl().startsWith("https://")) {
            return false;
        }
        
        // 检查是否为内网地址（看似安全的检查，但存在绕过可能）
        return !isInternalAddress(config.getSourceUrl());
    }

    // 检查是否为内网地址（存在逻辑漏洞）
    private boolean isInternalAddress(String url) {
        try {
            URL parsedUrl = new URL(url);
            String host = parsedUrl.getHost().toLowerCase();
            
            // 简单的黑名单检查（存在绕过可能）
            return host.contains("localhost") || 
                   host.contains("127.0.0.1") ||
                   host.contains("internal.");
        } catch (Exception e) {
            return true;
        }
    }

    // 下载原始数据（存在SSRF漏洞）
    private String downloadRawData(String sourceUrl) throws IOException {
        StringBuilder result = new StringBuilder();
        URL url = new URL(sourceUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(connection.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
        } catch (IOException e) {
            // 暴露部分响应信息（可能泄露内部系统信息）
            result.append("ERROR_RESPONSE: ").append(e.getMessage());
        }
        
        return result.toString();
    }

    // 数据清洗逻辑（模拟实现）
    private String cleanData(String rawData) {
        // 实际清洗逻辑...
        return rawData.replaceAll("\\s+", " ").trim();
    }

    // 存储清洗后数据（模拟实现）
    private void storeCleanedData(String cleanedData) {
        // 存储到数据库或缓存...
        System.out.println("Data stored successfully. Size: " + cleanedData.length());
    }

    // 记录错误信息（包含敏感信息）
    private void logError(String message) {
        System.err.println("[ERROR] " + message + " at " + new Date());
    }

    // 数据源配置类
    static class DataSourceConfig {
        private String sourceUrl;

        public String getSourceUrl() {
            return sourceUrl;
        }

        public void setSourceUrl(String sourceUrl) {
            this.sourceUrl = sourceUrl;
        }
    }
}