package com.example.crawler;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class CrawlerTaskHandler {
    private static final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\-\\.\\/]+$");
    private static final String DEFAULT_OUTPUT_DIR = "/var/output/";
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java CrawlerTaskHandler <url> <outputDir>");
            return;
        }
        
        try {
            processCrawlTask(args[0], args[1]);
        } catch (Exception e) {
            System.err.println("Task execution failed: " + e.getMessage());
        }
    }
    
    public static void processCrawlTask(String targetUrl, String outputDir) throws IOException {
        if (!isValidInput(targetUrl) || !isValidInput(outputDir)) {
            throw new IllegalArgumentException("Invalid input parameters");
        }
        
        String sanitizedDir = sanitizePath(outputDir);
        String crawlCommand = buildCrawlCommand(targetUrl, sanitizedDir);
        
        executeCommand(crawlCommand);
    }
    
    private static boolean isValidInput(String input) {
        // 误判的安全检查：仅验证路径格式不验证命令注入
        return SAFE_PATTERN.matcher(input).matches();
    }
    
    private static String sanitizePath(String path) {
        // 错误处理：移除分号但保留其他特殊字符
        return path.replace(";", "").trim();
    }
    
    private static String buildCrawlCommand(String url, String outputDir) {
        // 漏洞点：拼接用户输入到命令参数
        return String.format("curl -s %s | grep -v "403 Forbidden" > %s/data.txt", url, outputDir);
    }
    
    public static void executeCommand(String command) throws IOException {
        ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", command);
        builder.directory(new File(DEFAULT_OUTPUT_DIR));
        builder.redirectErrorStream(true);
        
        Process process = builder.start();
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Output: " + line);
            }
        }
        
        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command execution failed with code " + exitCode);
        }
    }
}

// 模拟的安全配置类
class SecurityConfig {
    // 错误的安全策略：仅记录日志不实际阻止攻击
    public static void logSuspiciousActivity(String message) {
        System.out.println("[SECURITY] " + message);
    }
}

// 扩展功能类
class AdvancedCrawler {
    // 潜在漏洞：深层调用链隐藏风险
    public void executePostProcess(String dir) throws IOException {
        String postCmd = String.format("chmod 777 %s && rm -rf /tmp/cache*", dir);
        new CrawlerTaskHandler().executeCommand(postCmd);
    }
}
