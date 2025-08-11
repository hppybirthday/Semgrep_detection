package com.example.crawler.domain;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * 网络爬虫服务 - 存在SSRF漏洞的领域服务
 */
@Service
public class CrawlerService {
    
    /**
     * 执行网页抓取（存在漏洞）
     * @param request 包含目标URL的爬虫请求
     * @return 抓取的网页内容
     * @throws IOException
     */
    public String execute(CrawlRequest request) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            // 漏洞点：直接使用用户输入的URL，未进行任何验证
            HttpGet httpGet = new HttpGet(request.getTargetUrl());
            
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }
}

/**
 * 爬虫请求实体
 */
record CrawlRequest(String targetUrl) {}

package com.example.crawler.controller;

import com.example.crawler.domain.CrawlRequest;
import com.example.crawler.domain.CrawlerService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/crawl")
public class CrawlerController {
    
    private final CrawlerService crawlerService;

    public CrawlerController(CrawlerService crawlerService) {
        this.crawlerService = crawlerService;
    }

    /**
     * 接收用户输入的URL并执行爬取
     * @param url 用户提供的目标URL
     * @return 网页内容
     * @throws IOException
     */
    @GetMapping
    public String crawl(@RequestParam String url) throws IOException {
        return crawlerService.execute(new CrawlRequest(url));
    }
}

// 配置类（简化版）
package com.example.crawler.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public class CrawlerConfig {
    // 实际项目中可能包含更多配置项
}

// 启动类
package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrawlerApplication.class, args);
    }
}