package com.example.crawler;

import java.sql.*;
import java.util.*;

// 高抽象建模的爬虫系统
interface Crawler {
    void crawl(String url);
    void saveData(String content, String pageId);
}

abstract class AbstractCrawler implements Crawler {
    protected Connection connection;
    
    public AbstractCrawler(String dbUrl, String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl, user, password);
    }
    
    protected abstract void processContent(String content);
}

// 具体爬虫实现
class WebCrawler extends AbstractCrawler {
    private Map<String, String> config = new HashMap<>();
    
    public WebCrawler(String dbUrl, String user, String password) throws SQLException {
        super(dbUrl, user, password);
        config.put("timeout", "5000");
    }
    
    @Override
    public void crawl(String url) {
        try {
            // 模拟网络请求
            String response = "<!DOCTYPE html><html><body>Content: " + 
                UUID.randomUUID().toString() + "</body></html>";
            saveData(response, url.split("=")[1]);
            processContent(response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @Override
    protected void processContent(String content) {
        // 实际解析逻辑
    }
    
    @Override
    public void saveData(String content, String pageId) {
        try {
            Statement stmt = connection.createStatement();
            // 漏洞点：直接拼接SQL语句
            String sql = "INSERT INTO pages (id, content, timestamp) VALUES ('" 
                + pageId + "', '" + content + "', NOW())";
            stmt.executeUpdate(sql);
            System.out.println("Data saved successfully");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public List<String> queryData(String filter) {
        List<String> results = new ArrayList<>();
        try {
            Statement stmt = connection.createStatement();
            // 漏洞点：过滤条件直接拼接
            String sql = "SELECT content FROM pages WHERE " + filter;
            ResultSet rs = stmt.executeQuery(sql);
            
            while (rs.next()) {
                results.add(rs.getString("content"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return results;
    }
}

// 爬虫控制器
class CrawlerController {
    private Crawler crawler;
    
    public CrawlerController(Crawler crawler) {
        this.crawler = crawler;
    }
    
    public void handleRequest(String url) {
        crawler.crawl(url);
    }
}

// 主程序入口
public class CrawlerApplication {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        try {
            // 初始化爬虫系统
            String dbUrl = "jdbc:mysql://localhost:3306/crawler_db";
            String dbUser = "root";
            String dbPassword = "password";
            
            Crawler crawler = new WebCrawler(dbUrl, dbUser, dbPassword);
            CrawlerController controller = new CrawlerController(crawler);
            
            // 模拟处理用户请求
            if (args.length > 0) {
                controller.handleRequest(args[0]);
            } else {
                controller.handleRequest("http://example.com/page?id=test123");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}