package com.example.crawler;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.nio.charset.*;
import java.util.*;

// 应用层
@RestController
@RequestMapping("/crawl")
public class CrawlerController {
    private final CrawlerApplicationService crawlerService;

    public CrawlerController() {
        this.crawlerService = new CrawlerApplicationService();
    }

    @GetMapping
    public CrawlResponse crawl(@RequestParam String targetUrl) {
        try {
            return crawlerService.fetchContent(targetUrl);
        } catch (Exception e) {
            return new CrawlResponse("Error: " + e.getMessage(), 500);
        }
    }
}

// 领域服务
class CrawlerApplicationService {
    private final CrawlerInfrastructureClient client;

    public CrawlerApplicationService() {
        this.client = new CrawlerInfrastructureClient();
    }

    public CrawlResponse fetchContent(String targetUrl) throws Exception {
        // 未对用户输入的URL进行任何安全验证
        return client.fetchFromTarget(targetUrl);
    }
}

// 基础设施层
class CrawlerInfrastructureClient {
    public CrawlResponse fetchFromTarget(String targetUrl) throws Exception {
        URL url = new URL(targetUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        int responseCode = connection.getResponseCode();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(responseCode < 400 
                ? connection.getInputStream() 
                : connection.getErrorStream(),
            StandardCharsets.UTF_8));

        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\
");
        }
        reader.close();

        return new CrawlResponse(content.toString(), responseCode);
    }
}

// 领域模型
record CrawlResponse(String content, int statusCode) {}
