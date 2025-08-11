package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@SpringBootApplication
public class CrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrawlerApplication.class, args);
    }

    @RestController
    @RequestMapping("/api/crawl")
    public class CrawlController {
        private final CrawlerService crawlerService = new CrawlerService();

        @PostMapping
        public ResponseEntity<String> crawl(@RequestBody CrawlRequest request) {
            try {
                String result = crawlerService.fetchContent(request.getUrl(), request.getTimeout());
                return ResponseEntity.ok(result);
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
            }
        }
    }

    public static class CrawlRequest {
        private String url;
        private int timeout;

        // Getters and setters
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public int getTimeout() { return timeout; }
        public void setTimeout(int timeout) { this.timeout = timeout; }
    }

    public static class CrawlerService {
        public String fetchContent(String targetUrl, int timeout) throws IOException, InterruptedException {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))  // 直接使用用户输入的URL
                    .timeout(java.time.Duration.ofSeconds(timeout))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.body();
        }
    }
}