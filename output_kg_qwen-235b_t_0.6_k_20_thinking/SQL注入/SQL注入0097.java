package com.example.crawler.domain;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 领域实体
public class CrawledUrl {
    private String id;
    private String url;
    private String content;
    
    // 省略getter/setter
}

// 仓储接口
interface CrawledUrlRepository {
    List<CrawledUrl> findByUrl(String url);
    void save(CrawledUrl crawledUrl);
}

// 仓储实现
@Service
class JdbcCrawledUrlRepository implements CrawledUrlRepository {
    
    @Autowired
    private DataSource dataSource;
    
    @Override
    public List<CrawledUrl> findByUrl(String url) {
        List<CrawledUrl> results = new ArrayList<>();
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                 "SELECT * FROM crawled_urls WHERE url = '" + url + "'")) { // 漏洞点：直接拼接SQL
            
            while (rs.next()) {
                CrawledUrl urlEntity = new CrawledUrl();
                urlEntity.setId(rs.getString("id"));
                urlEntity.setUrl(rs.getString("url"));
                urlEntity.setContent(rs.getString("content"));
                results.add(urlEntity);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return results;
    }
    
    @Override
    public void save(CrawledUrl crawledUrl) {
        String sql = "INSERT INTO crawled_urls(url, content) VALUES('"
                + crawledUrl.getUrl() + "', '" 
                + crawledUrl.getContent() + "')"; // 漏洞点
        
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

// 领域服务
@Service
class CrawlerService {
    
    @Autowired
    private CrawledUrlRepository repository;
    
    public List<CrawledUrl> searchUrls(String urlPattern) {
        return repository.findByUrl(urlPattern);
    }
    
    public void storeCrawledData(String url, String content) {
        CrawledUrl crawledUrl = new CrawledUrl();
        crawledUrl.setUrl(url);
        crawledUrl.setContent(content);
        repository.save(crawledUrl);
    }
}

// 控制器
@RestController
@RequestMapping("/api/crawler")
class CrawlerController {
    
    @Autowired
    private CrawlerService crawlerService;
    
    @GetMapping("/search")
    public List<CrawledUrl> search(@RequestParam String url) {
        return crawlerService.searchUrls(url); // 漏洞入口
    }
    
    @PostMapping("/crawl")
    public void crawl(@RequestParam String url) {
        String crawledContent = "模拟抓取的页面内容";
        crawlerService.storeCrawledData(url, crawledContent);
    }
}