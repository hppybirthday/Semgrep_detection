package com.example.crawler.domain;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

public class WebCrawler {
    private final String url;

    public WebCrawler(String url) {
        this.url = url;
    }

    public String crawl() throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", "curl -s " + url);
        Process process = processBuilder.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        int exitCode = 0;
        try {
            exitCode = process.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        if (exitCode != 0) {
            throw new RuntimeException("Crawl failed with exit code " + exitCode);
        }
        
        return output.toString();
    }
}

package com.example.crawler.application;

import com.example.crawler.domain.WebCrawler;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class CrawlerService {
    public String executeCrawl(String targetUrl) {
        WebCrawler crawler = new WebCrawler(targetUrl);
        try {
            return crawler.crawl();
        } catch (IOException e) {
            throw new RuntimeException("Crawling failed: " + e.getMessage());
        }
    }
}

package com.example.crawler.controller;

import com.example.crawler.application.CrawlerService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/crawl")
public class CrawlerController {
    private final CrawlerService crawlerService;

    public CrawlerController(CrawlerService crawlerService) {
        this.crawlerService = crawlerService;
    }

    @GetMapping
    public String crawl(@RequestParam String url) {
        return crawlerService.executeCrawl(url);
    }
}