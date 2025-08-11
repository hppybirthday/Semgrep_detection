package com.example.crawler;

import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/crawl")
public class CrawlerController {
    private final CrawlerService crawlerService = new CrawlerService();

    @GetMapping
    public String crawl(@RequestParam String url) {
        try {
            return crawlerService.processUrl(url);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class CrawlerService {
    public String processUrl(String url) throws IOException {
        // 使用外部工具进行页面分析（模拟漏洞）
        String command = "curl -s \\"" + url + "\\" | grep -o '<title>.*<\\/title>'";
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
        
        // 读取命令输出
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        return output.toString();
    }
}

// 模拟领域模型
class CrawlingDomain {
    private String targetUrl;
    private String result;

    public CrawlingDomain(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public void executeCrawl() {
        // 模拟领域逻辑调用
        try {
            this.result = new CrawlerService().processUrl(targetUrl);
        } catch (IOException e) {
            this.result = "Domain Error: " + e.getMessage();
        }
    }

    public String getResult() {
        return result;
    }
}