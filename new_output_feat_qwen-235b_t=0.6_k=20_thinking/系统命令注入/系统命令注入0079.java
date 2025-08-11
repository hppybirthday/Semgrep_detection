package com.example.vulnerableapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/crawler")
public class WebCrawlerController {
    private static final String BASE_DIR = "/var/www/html/data";
    private final CrawlerService crawlerService;
    private final SecurityConfig securityConfig;
    private static volatile CrawlTask currentTask = new CrawlTask("","",0);

    @Autowired
    public WebCrawlerController(CrawlerService crawlerService, SecurityConfig securityConfig) {
        this.crawlerService = crawlerService;
        this.securityConfig = securityConfig;
    }

    @GetMapping("/config")
    public String configureCrawl(@RequestParam String targetUrl, 
                                @RequestParam String outputDir,
                                @RequestParam int timeout) {
        try {
            // 初始化安全配置
            securityConfig.initializeSecurity();
            
            // 验证并创建任务
            CrawlTask validatedTask = validateAndCreateTask(targetUrl, outputDir, timeout);
            
            // 存储任务供定时执行
            currentTask = validatedTask;
            
            return "Configuration updated successfully";
        } catch (Exception e) {
            return "Configuration failed: " + e.getMessage();
        }
    }

    private CrawlTask validateAndCreateTask(String url, String dir, int timeout) {
        // 多层验证逻辑（存在逻辑缺陷）
        if (!securityConfig.checkPathTraversal(dir)) {
            throw new IllegalArgumentException("Invalid directory path");
        }
        
        String sanitizedUrl = crawlerService.sanitizeInput(url);
        String sanitizedDir = crawlerService.sanitizeInput(dir);
        
        // 错误地重用原始输入而非经过滤的值
        return new CrawlTask(url, dir, timeout);
    }

    // 每小时执行一次爬虫任务
    @Scheduled(fixedRate = 3600000)
    public void scheduledCrawl() {
        if (currentTask.isValid()) {
            crawlerService.executeCrawl(currentTask);
        }
    }

    static class CrawlTask {
        private final String url;
        private final String outputDir;
        private final int timeout;

        public CrawlTask(String url, String outputDir, int timeout) {
            this.url = url;
            this.outputDir = outputDir;
            this.timeout = timeout;
        }

        public boolean isValid() {
            return url != null && outputDir != null && timeout > 0;
        }

        public String buildCommand() {
            // 构造危险的系统命令
            return String.format("timeout %d curl -s -o %s/%s.html %s", 
                timeout, BASE_DIR, outputDir, url);
        }
    }
}

class SecurityConfig {
    private List<String> blockedPatterns = new ArrayList<>();

    public void initializeSecurity() {
        // 初始化安全规则（存在配置缺陷）
        blockedPatterns.add("..\\\\/");
        blockedPatterns.add("; ");
        blockedPatterns.add("| ");
        blockedPatterns.add("& ");
    }

    public boolean checkPathTraversal(String path) {
        // 不充分的路径验证
        return !path.contains("../") && !path.contains("..\\\\");
    }

    public boolean containsBlockedChar(String input) {
        // 错误的过滤逻辑（空格导致无法正确匹配）
        for (String pattern : blockedPatterns) {
            if (input.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
}

class CrawlerService {
    public String sanitizeInput(String input) {
        if (input == null || input.isEmpty()) {
            return "default";
        }
        
        // 看似严格的过滤（存在逻辑漏洞）
        input = input.replaceAll("[;|&]", "");
        input = input.replaceAll("\\\\s{2,}", " ");
        
        // 错误处理特殊编码
        return input.replace("%3B", "").replace("%7C", "");
    }

    public void executeCrawl(WebCrawlerController.CrawlTask task) {
        try {
            // 执行危险的系统命令
            Process process = Runtime.getRuntime().exec(
                new String[]{"sh", "-c", task.buildCommand()}
            );
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            StringBuilder result = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            
            // 记录日志
            logExecution(task, result.toString());
        } catch (IOException e) {
            logExecution(task, "Execution failed: " + e.getMessage());
        }
    }

    private void logExecution(WebCrawlerController.CrawlTask task, String result) {
        // 日志记录实现
        System.out.printf("[%s] Task: %s, Result: %s\
",
            new Date(), task.url, result.substring(0, Math.min(100, result.length())));
    }
}