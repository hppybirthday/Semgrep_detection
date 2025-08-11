package com.example.vulnerablecrawler;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/crawl")
public class VulnerableCrawlerController {
    private static final Logger logger = LoggerFactory.getLogger(VulnerableCrawlerController.class);

    @PostMapping("/process")
    public String processCrawledData(@RequestParam String payload) {
        try {
            // 模拟爬虫接收远程数据并反序列化处理
            byte[] decodedBytes = Base64.getDecoder().decode(payload);
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decodedBytes);
            ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
            
            // 存在漏洞的反序列化操作
            Object deserialized = objectInputStream.readObject();
            
            // 模拟处理爬取结果
            if (deserialized instanceof CrawlResult) {
                CrawlResult result = (CrawlResult) deserialized;
                logger.info("Processed crawl result: {}", result.getUrl());
                return "Success";
            }
            
            return "Invalid data type";
            
        } catch (Exception e) {
            logger.error("Deserialization error: {}", e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    @GetMapping("/health")
    public String healthCheck() {
        return "Service is running";
    }

    // 可序列化的业务类
    public static class CrawlResult implements Serializable {
        private String url;
        private String content;
        
        public CrawlResult(String url, String content) {
            this.url = url;
            this.content = content;
        }

        public String getUrl() { return url; }
        public String getContent() { return content; }
    }
}