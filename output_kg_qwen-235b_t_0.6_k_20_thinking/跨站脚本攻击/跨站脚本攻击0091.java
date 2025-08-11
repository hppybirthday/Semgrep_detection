package com.example.crawler;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import java.util.ArrayList;
import java.util.List;

// 聚合根
public class CrawlerApplication {
    private final ContentRepository contentRepository = new ContentRepository();

    public static void main(String[] args) {
        CrawlerApplication app = new CrawlerApplication();
        app.startCrawling("https://example.com");
    }

    public void startCrawling(String url) {
        CrawlerService crawler = new CrawlerService();
        List<Content> contents = crawler.crawl(url);
        
        // 保存并展示内容
        for (Content content : contents) {
            contentRepository.save(content);
            System.out.println(generateContentPage(content));
        }
    }

    // 漏洞点：未转义直接拼接HTML
    private String generateContentPage(Content content) {
        Document doc = Jsoup.parse("<html><body><h1>Content</h1><div id='content'></div></body></html>");
        Element contentDiv = doc.getElementById("content");
        
        // 危险操作：直接插入原始HTML
        contentDiv.html(content.getRawContent());
        
        return doc.outerHtml();
    }
}

// 实体
class Content {
    private String rawContent;
    private String url;

    public Content(String rawContent, String url) {
        this.rawContent = rawContent;
        this.url = url;
    }

    public String getRawContent() {
        return rawContent;
    }
    
    public String getUrl() {
        return url;
    }
}

// 值对象
class CrawlResult {
    List<Content> contents = new ArrayList<>();
    
    public void addContent(Content content) {
        contents.add(content);
    }
}

// 服务
class CrawlerService {
    public List<Content> crawl(String url) {
        List<Content> results = new ArrayList<>();
        try {
            Document doc = Jsoup.connect(url).get();
            // 模拟提取内容
            results.add(new Content(doc.body().html(), url));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return results;
    }
}

// 仓储
class ContentRepository {
    private List<Content> storage = new ArrayList<>();

    public void save(Content content) {
        storage.add(content);
    }

    public List<Content> findAll() {
        return new ArrayList<>(storage);
    }
}