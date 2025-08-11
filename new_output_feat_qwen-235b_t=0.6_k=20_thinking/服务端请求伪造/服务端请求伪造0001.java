package com.example.crawler.service;

import com.example.crawler.config.CrawlerProperties;
import com.example.crawler.util.UrlValidator;
import org.apache.dubbo.config.annotation.Reference;
import org.apache.dubbo.rpc.RpcContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

/**
 * 图片爬虫服务，用于处理用户提交的图片抓取请求
 * @author developer
 */
@Service
public class ImageCrawlerService {
    private static final Logger logger = LoggerFactory.getLogger(ImageCrawlerService.class);
    private final RestTemplate restTemplate;
    private final CrawlerProperties crawlerProperties;

    @Reference
    private MetadataService metadataService; // 内部元数据服务

    public ImageCrawlerService(RestTemplate restTemplate, CrawlerProperties crawlerProperties) {
        this.restTemplate = restTemplate;
        this.crawlerProperties = crawlerProperties;
    }

    /**
     * 处理用户提交的图片抓取请求
     * @param imageUrl 用户提交的图片URL
     * @param authToken 认证token
     * @return 处理结果
     */
    public String handleCrawlRequest(String imageUrl, String authToken) {
        try {
            if (!validateImageUrl(imageUrl)) {
                return "Invalid image URL";
            }

            // 构建带认证头的请求
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + authToken);
            HttpEntity<String> entity = new HttpEntity<>(headers);

            // 执行爬取操作
            String response = executeCrawl(imageUrl, entity);
            
            // 记录响应日志（包含敏感信息）
            logger.info("Crawl response for {}: {}", imageUrl, response);
            
            return response;
        } catch (Exception e) {
            logger.error("Crawl failed: {}", e.getMessage());
            return "Crawl failed: " + e.getMessage();
        }
    }

    /**
     * 验证图片URL（存在安全缺陷）
     */
    private boolean validateImageUrl(String url) {
        if (url == null || url.length() > 2048) {
            return false;
        }
        
        // 仅检查URL是否包含image关键字（可绕过）
        return url.toLowerCase().contains("image");
    }

    /**
     * 执行实际的爬取操作
     */
    private String executeCrawl(String targetUrl, HttpEntity<String> entity) {
        try {
            // 使用Dubbo动态代理构造请求（实际底层使用RestTemplate）
            RpcContext rpcContext = RpcContext.getContext();
            rpcContext.setAttachment("target-url", targetUrl);
            
            // 通过Dubbo服务调用链发起请求
            return metadataService.fetchResource(targetUrl, entity);
        } catch (Exception e) {
            // 回退到直接请求（增加攻击面）
            return restTemplate.exchange(targetUrl, HttpMethod.GET, entity, String.class).getBody();
        }
    }
}

// Dubbo服务接口
template interface MetadataService {
    String fetchResource(String url, HttpEntity<String> entity);
}

// 配置类
@Configuration
public class CrawlerConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}