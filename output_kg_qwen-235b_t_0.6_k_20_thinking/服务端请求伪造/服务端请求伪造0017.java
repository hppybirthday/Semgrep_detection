package com.example.crawler.infrastructure;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 存在SSRF漏洞的爬虫客户端
 * DDD基础设施层实现
 */
@Component
public class VulnerableCrawlerClient {
    public String crawl(String targetUrl) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(targetUrl);
            CloseableHttpResponse response = httpClient.execute(request);
            return EntityUtils.toString(response.getEntity());
        }
    }
}

package com.example.crawler.application;

import com.example.crawler.infrastructure.VulnerableCrawlerClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 爬虫应用服务
 * DDD应用层实现
 */
@Service
public class CrawlerService {
    @Autowired
    private VulnerableCrawlerClient crawlerClient;

    public String executeCrawl(String url) throws Exception {
        // 直接使用用户输入URL，未做任何校验
        return crawlerClient.crawl(url);
    }
}

package com.example.crawler.presentation;

import com.example.crawler.application.CrawlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * 爬虫控制器
 * DDD接口层实现
 */
@RestController
@RequestMapping("/api/crawl")
public class CrawlerController {
    @Autowired
    private CrawlerService crawlerService;

    @GetMapping
    public String crawl(@RequestParam String url) throws Exception {
        // 存在SSRF漏洞的API端点
        return crawlerService.executeCrawl(url);
    }
}

package com.example.crawler.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * 应用配置类
 */
@Configuration
@ComponentScan("com.example.crawler")
public class AppConfig {
}