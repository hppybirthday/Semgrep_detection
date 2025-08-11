package com.example.vulnerablecrawler;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

interface Crawler {
    String crawl(String url) throws CrawlException;
}

class WebCrawler implements Crawler {
    private final CommandExecutor executor;

    public WebCrawler(CommandExecutor executor) {
        this.executor = executor;
    }

    @Override
    public String crawl(String url) throws CrawlException {
        try {
            String[] command = {"curl", url};
            return executor.execute(command);
        } catch (IOException | InterruptedException e) {
            throw new CrawlException("Crawl failed: " + e.getMessage());
        }
    }
}

class CommandExecutor {
    public String execute(String[] command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(command);
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        process.waitFor();
        return output.toString();
    }
}

class CrawlException extends Exception {
    public CrawlException(String message) {
        super(message);
    }
}

@RestController
class CrawlController {
    private final Crawler crawler;

    public CrawlController() {
        this.crawler = new WebCrawler(new CommandExecutor());
    }

    @GetMapping("/crawl")
    public String handleCrawl(@RequestParam String url) {
        try {
            return crawler.crawl(url);
        } catch (CrawlException e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 漏洞触发示例：
// /crawl?url=http://example.com;rm%20-rf%20/tmp/test