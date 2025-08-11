package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@SpringBootApplication
public class XssCrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssCrawlerApplication.class, args);
    }
}

@Controller
class CrawlerController {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/crawl")
    public String crawl(@RequestParam String url) {
        try {
            // 使用HttpClient爬取目标网页
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String rawContent = response.body();
            
            // 存在漏洞的代码：直接将原始HTML内容嵌入响应
            return "<html><body>" + 
                  "<h2>Crawled Content:</h2>" + 
                  "<div style='border:1px solid #ccc;padding:10px;'>" + 
                  rawContent + 
                  "</div>" + 
                  "</body></html>";
            
        } catch (Exception e) {
            return "<html><body>Error crawling URL</body></html>";
        }
    }

    @GetMapping("/search")
    public String search(@RequestParam String query) {
        // 模拟搜索引擎爬取过程
        String targetUrl = "https://example.com/search?q=" + query;
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            String rawContent = response.body();
            
            // 第二个漏洞点：搜索参数未过滤直接用于DOM操作
            return "<html><body>" +
                  "<script>document.write('<h3>Results for: " + query + "</h3>');<\/script>" +
                  "<div style='border:1px solid #ccc;padding:10px;'>" + 
                  rawContent + 
                  "</div>" + 
                  "</body></html>";
            
        } catch (Exception e) {
            return "<html><body>Error searching</body></html>";
        }
    }
}