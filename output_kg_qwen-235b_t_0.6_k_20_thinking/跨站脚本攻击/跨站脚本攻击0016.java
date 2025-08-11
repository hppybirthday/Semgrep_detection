package com.example.crawler;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * 网络爬虫核心服务
 * 领域驱动设计中的应用服务层
 */
@Service
public class CrawlerService {
    
    /**
     * 执行网页爬取操作
     * @param url 待爬取的URL
     * @return 爬取结果对象
     * @throws IOException 网络异常
     */
    public CrawlerResult crawl(String url) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                String htmlContent = EntityUtils.toString(response.getEntity());
                return new CrawlerResult(url, htmlContent);
            }
        }
    }
}

/**
 * 爬取结果领域模型
 */
record CrawlerResult(String url, String htmlContent) {}

import org.springframework.web.bind.annotation.*;

/**
 * 网络爬虫控制器
 * 领域驱动设计中的接口适配层
 */
@RestController
@RequestMapping("/crawl")
public class WebController {
    private final CrawlerService crawlerService;

    public WebController(CrawlerService crawlerService) {
        this.crawlerService = crawlerService;
    }

    /**
     * 爬取并展示网页内容
     * @param url 待爬取的URL
     * @return HTML格式的展示结果
     * @throws IOException 网络异常
     */
    @GetMapping
    public String getCrawlResult(@RequestParam String url) throws IOException {
        CrawlerResult result = crawlerService.crawl(url);
        // 直接将原始HTML内容插入响应页面（存在XSS漏洞）
        return "<html><body><h1>爬取结果 - " + result.url() + "</h1>" +
               "<div style='border:1px solid #ccc;padding:10px;'>" +
               result.htmlContent() + "</div></body></html>";
    }
}