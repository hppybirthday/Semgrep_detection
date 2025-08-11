package com.example.crawler;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

@SpringBootApplication
public class CrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrawlerApplication.class, args);
    }
}

@Service
class CrawlerService {
    public String fetchPageContent(String url) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}

@Service
class PageParser {
    public List<String> extractComments(String html) {
        Document doc = Jsoup.parse(html);
        List<String> comments = new ArrayList<>();
        for (Element commentElement : doc.select(".user-comment")) {
            // 直接提取原始HTML内容，未做任何转义处理
            comments.add(commentElement.html());
        }
        return comments;
    }
}

@Service
class ContentRepository {
    private List<String> storedComments = new ArrayList<>();

    public void saveComments(List<String> comments) {
        storedComments.addAll(comments);
    }

    public List<String> getStoredComments() {
        return storedComments;
    }
}

@RestController
@RequestMapping("/comments")
class CommentController {
    private final ContentRepository repository;

    public CommentController(ContentRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public String listComments() {
        StringBuilder html = new StringBuilder("<html><body><h1>Comments:</h1>");
        for (String comment : repository.getStoredComments()) {
            // 直接拼接用户内容到HTML，存在XSS漏洞
            html.append("<div>").append(comment).append("</div>");
        }
        html.append("</body></html>");
        return html.toString();
    }
}

// 漏洞入口点示例：
// curl "http://localhost:8080/crawl?url=https://malicious-site.com/comments"
@RestController
@RequestMapping("/crawl")
class CrawlController {
    private final CrawlerService crawler;
    private final PageParser parser;
    private final ContentRepository repository;

    public CrawlController(CrawlerService crawler, PageParser parser, ContentRepository repository) {
        this.crawler = crawler;
        this.parser = parser;
        this.repository = repository;
    }

    @GetMapping
    public String crawl(@RequestParam String url) throws Exception {
        String htmlContent = crawler.fetchPageContent(url);
        List<String> comments = parser.extractComments(htmlContent);
        repository.saveComments(comments);
        return "Crawled and stored comments from " + url;
    }
}