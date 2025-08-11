package com.example.vulnerablecrawler;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;

@RestController
@RequestMapping("/crawl")
public class WebCrawlerController {
    // 基础目录（意图限制访问范围）
    private static final String BASE_DIR = "/var/www/html/archive/";

    @GetMapping("/download")
    public String downloadPage(@RequestParam String url, @RequestParam String savePath) {
        try {
            // 漏洞点：直接拼接用户输入的保存路径
            File targetFile = new File(BASE_DIR + savePath);
            
            // 确保目录存在
            targetFile.getParentFile().mkdirs();
            
            // 下载网页内容
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestMethod("GET");
            
            try (InputStream in = connection.getInputStream();
                 OutputStream out = new FileOutputStream(targetFile)) {
                
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            
            return "Page saved to: " + targetFile.getAbsolutePath();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟启动类（简化版）
    public static void main(String[] args) {
        // 实际应使用Spring Boot启动
        System.out.println("WebCrawler started at " + BASE_DIR);
    }
}

/*
攻击示例：
/crawl/download?url=http://example.com/index.html&savePath=../../../../etc/passwd
将导致下载内容写入系统文件/etc/passwd
*/