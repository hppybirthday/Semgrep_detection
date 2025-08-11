package com.example.vulnerablecrawler;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/crawl")
public class VulnerableCrawlerController {
    
    @GetMapping
    public String crawl(@RequestParam String url) {
        try {
            // 模拟声明式配置的爬虫执行器
            ProcessBuilder builder = new ProcessBuilder();
            List<String> command = new ArrayList<>();
            
            // 漏洞点：直接拼接用户输入到命令中
            if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                command.add("cmd.exe");
                command.add("/c");
                command.add("curl " + url);  // Windows系统使用curl
            } else {
                command.add("sh");
                command.add("-c");
                command.add("wget -O- " + url);  // Linux系统使用wget
            }
            
            builder.command(command);
            Process process = builder.start();
            
            // 读取命令输出结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            return "Crawled content:\
" + result.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟声明式配置的错误处理
    @ExceptionHandler(IOException.class)
    public String handleIOException() {
        return "System command execution failed";
    }
    
    // 模拟声明式配置的健康检查
    @GetMapping("/health")
    public String healthCheck() {
        return "Crawler service is running";
    }
}

// 漏洞配置类（声明式编程风格）
@Configuration
class CrawlerConfig {
    @Bean
    public Properties crawlerProperties() {
        Properties props = new Properties();
        props.setProperty("crawler.timeout", "30s");
        props.setProperty("crawler.userAgent", "VulnerableBot/1.0");
        return props;
    }
}