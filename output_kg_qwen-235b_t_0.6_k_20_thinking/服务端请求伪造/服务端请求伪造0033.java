package com.example.crawler;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class VulnerableCrawler {
    public String crawl(String targetUrl) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(targetUrl);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }
}

package com.example.crawler;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CrawlerController {
    private final VulnerableCrawler crawler;

    public CrawlerController(VulnerableCrawler crawler) {
        this.crawler = crawler;
    }

    @GetMapping("/crawl")
    public String handleCrawl(@RequestParam String url) {
        try {
            return crawler.crawl(url);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// Spring Boot主类（需单独文件）
package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}