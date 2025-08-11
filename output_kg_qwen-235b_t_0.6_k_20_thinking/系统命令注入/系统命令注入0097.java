package com.example.crawler.infrastructure;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class CommandExecutor {
    public String execCrawlCommand(String url) {
        StringBuilder output = new StringBuilder();
        try {
            // 模拟使用curl进行网页抓取
            Process process = Runtime.getRuntime().exec("curl -s " + url);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            process.waitFor();
            
        } catch (Exception e) {
            output.append("Error executing command: ").append(e.getMessage());
        }
        return output.toString();
    }
}

package com.example.crawler.domain;

import com.example.crawler.infrastructure.CommandExecutor;

public class Crawler {
    private CommandExecutor executor;

    public Crawler(CommandExecutor executor) {
        this.executor = executor;
    }

    public String crawl(String targetUrl) {
        // 未验证或清理用户输入
        return executor.execCrawlCommand(targetUrl);
    }
}

package com.example.crawler.application;

import com.example.crawler.domain.Crawler;
import com.example.crawler.infrastructure.CommandExecutor;

public class CrawlerService {
    private Crawler crawler;

    public CrawlerService() {
        this.crawler = new Crawler(new CommandExecutor());
    }

    public String startCrawl(String url) {
        return crawler.crawl(url);
    }
}

package com.example.crawler.controller;

import com.example.crawler.application.CrawlerService;

public class CrawlerController {
    private CrawlerService service;

    public CrawlerController() {
        this.service = new CrawlerService();
    }

    // 模拟HTTP接口调用
    public String handleRequest(String urlParam) {
        if (urlParam == null || urlParam.isEmpty()) {
            return "Usage: /crawl?url=<target>";
        }
        return service.startCrawl(urlParam);
    }

    public static void main(String[] args) {
        CrawlerController controller = new CrawlerController();
        // 示例调用（攻击者可能通过参数注入）
        String result = controller.handleRequest(
            "http://example.com; rm -rf /tmp/test; echo \\"Malicious command executed\\""
        );
        System.out.println("Output:\
" + result);
    }
}

// DTO用于接口通信
class ResponseDTO {
    private String content;
    private boolean success;

    // Getters and setters
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }
}