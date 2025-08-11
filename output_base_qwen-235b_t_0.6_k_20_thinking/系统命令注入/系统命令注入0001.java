package com.example.vulnerablecrawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
public class VulnerableCrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawlerApplication.class, args);
    }
}

@RestController
class CrawlerController {
    @GetMapping("/crawl")
    public String crawl(@RequestParam String url) {
        try {
            CrawlerService crawler = new CrawlerService();
            return crawler.fetchContent(url);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class CrawlerService {
    public String fetchContent(String url) throws IOException, InterruptedException {
        // 模拟使用系统命令进行网络请求
        ProcessBuilder processBuilder = new ProcessBuilder("sh", "-c", "curl -s " + url);
        
        // 漏洞点：直接拼接用户输入到命令中
        // 恶意输入示例：http://example.com; rm -rf /
        Process process = processBuilder.start();
        
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
        }
        
        return output.toString();
    }
}