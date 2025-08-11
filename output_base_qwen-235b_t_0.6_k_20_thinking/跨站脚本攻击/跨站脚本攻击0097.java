package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class VulnerableCrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawlerApplication.class, args);
    }
}

@Entity
class CrawledPage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String url;
    private String content;

    // Getters and setters
}

interface CrawlRepository extends JpaRepository<CrawledPage, Long> {}

@Service
class WebCrawlerService {
    public CrawledPage crawlPage(String url) {
        // 模拟爬取过程
        String maliciousContent = "<script>alert('XSS');<\/script>";
        return new CrawledPage() {{
            setUrl(url);
            setContent("<html><body>Malicious content: " + maliciousContent + "<\/body><\/html>");
        }};
    }
}

@RestController
@RequestMapping("/crawl")
class WebCrawlerController {
    private final WebCrawlerService crawlerService;
    private final CrawlRepository crawlRepository;

    public WebCrawlerController(WebCrawlerService crawlerService, CrawlRepository crawlRepository) {
        this.crawlerService = crawlerService;
        this.crawlRepository = crawlRepository;
    }

    @GetMapping
    public String crawl(@RequestParam String url) {
        CrawledPage page = crawlerService.crawlPage(url);
        crawlRepository.save(page);
        return generateHtmlReport(page);
    }

    private String generateHtmlReport(CrawledPage page) {
        return "<html><head><title>Report<\/title><\/head>" +
               "<body><h1>Page Content: " + page.getUrl() + "<\/h1>" +
               "<pre>" + page.getContent() + "<\/pre><\/body><\/html>";
    }
}