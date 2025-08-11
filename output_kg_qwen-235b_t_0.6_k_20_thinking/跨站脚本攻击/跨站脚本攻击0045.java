package com.example.crawler.xss;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

// 高抽象建模风格的爬虫系统
public class XssCrawlerSystem {
    public static void main(String[] args) {
        Crawler crawler = new WebCrawler();
        ResultRenderer renderer = new HtmlResultRenderer();
        
        try {
            // 抓取存在恶意内容的网页
            CrawlResult result = crawler.crawl("https://malicious.example.com");
            // 渲染包含XSS漏洞的结果页面
            System.out.println(renderer.renderResultPage(result));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// 爬虫接口
interface Crawler {
    CrawlResult crawl(String url) throws IOException;
}

// 抽象爬虫基类
abstract class AbstractCrawler implements Crawler {
    protected Document fetchDocument(String url) throws IOException {
        return Jsoup.parse(new URL(url), 5000);
    }
}

// 具体网页爬虫实现
class WebCrawler extends AbstractCrawler {
    @Override
    public CrawlResult crawl(String url) throws IOException {
        Document doc = fetchDocument(url);
        // 存在漏洞的实现：直接提取原始HTML内容
        String title = doc.title(); // 恶意页面可能包含<script>标签
        String content = doc.body().html(); // 直接获取原始HTML内容
        return new CrawlResult(title, content);
    }
}

// 结果数据模型
class CrawlResult {
    private final String title;
    private final String content;
    
    public CrawlResult(String title, String content) {
        this.title = title;
        this.content = content;
    }
    
    public String getTitle() { return title; }
    public String getContent() { return content; }
}

// 结果渲染器
class ResultRenderer {
    // 存在XSS漏洞的渲染方法
    public String renderResultPage(CrawlResult result) {
        // 漏洞点：直接拼接用户输入内容到HTML
        return "<!DOCTYPE html>\
" +
               "<html><head><title>" + result.getTitle() + "</title></head>\
" +
               "<body>\
" +
               "<h1>" + result.getTitle() + "</h1>\
" + // 未转义标题内容
               "<div class=\\"content\\">" + result.getContent() + "</div>\
" + // 直接插入原始HTML
               "</body></html>";
    }
}

// 高抽象建模风格的辅助类
class HtmlResultRenderer extends ResultRenderer {}