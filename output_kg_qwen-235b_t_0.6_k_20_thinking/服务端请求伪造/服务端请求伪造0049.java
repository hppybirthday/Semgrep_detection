package com.example.crawler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

// 高抽象建模风格接口
interface Crawler {
    String fetchContent(String targetUrl) throws IOException;
}

// 核心爬虫实现类
class DefaultCrawler implements Crawler {
    @Override
    public String fetchContent(String targetUrl) throws IOException {
        // 漏洞核心：直接使用用户输入的URL
        URL url = new URL(targetUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // 读取响应
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }
}

// 爬虫服务管理类
class CrawlerService {
    private final Crawler crawler;
    private final Map<String, String> requestCache = new HashMap<>();

    public CrawlerService(Crawler crawler) {
        this.crawler = crawler;
    }

    public String processRequest(String targetUrl) {
        if (requestCache.containsKey(targetUrl)) {
            return requestCache.get(targetUrl);
        }
        
        try {
            // 未进行任何安全校验直接发起请求
            String result = crawler.fetchContent(targetUrl);
            requestCache.put(targetUrl, result);
            return result;
        } catch (IOException e) {
            throw new RuntimeException("Crawling failed: " + e.getMessage(), e);
        }
    }
}

// 模拟的Web控制器类
class CrawlerController {
    private final CrawlerService crawlerService;

    public CrawlerController(CrawlerService crawlerService) {
        this.crawlerService = crawlerService;
    }

    // 模拟HTTP端点
    public String handleCrawlRequest(String urlParam) {
        if (urlParam == null || urlParam.isEmpty()) {
            return "Missing URL parameter";
        }
        
        // 直接使用用户输入的URL参数
        return crawlerService.processRequest(urlParam);
    }
}

// 主程序入口
public class SsrfDemoApplication {
    public static void main(String[] args) {
        // 初始化组件
        Crawler crawler = new DefaultCrawler();
        CrawlerService crawlerService = new CrawlerService(crawler);
        CrawlerController controller = new CrawlerController(crawlerService);
        
        // 模拟用户输入（攻击示例）
        String userInputUrl = "http://localhost:8080/admin/config";
        try {
            System.out.println("Fetching content...");
            String result = controller.handleCrawlRequest(userInputUrl);
            System.out.println("Response: " + result);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}