import java.sql.*;
import java.util.*;

// 高抽象建模：爬虫配置类
class CrawlerConfig {
    String dbUrl = "jdbc:mysql://localhost:3306/crawler_db";
    String dbUser = "root";
    String dbPassword = "secret";
    String userAgent = "MaliciousSpider/1.0";
}

// 数据实体抽象
class CrawledData {
    String url;
    String content;
    
    CrawledData(String url, String content) {
        this.url = url;
        this.content = content;
    }
}

// 数据存储模块
class DataStorage {
    private Connection connection;
    
    DataStorage(CrawlerConfig config) throws SQLException {
        connection = DriverManager.getConnection(
            config.dbUrl, 
            config.dbUser, 
            config.dbPassword
        );
    }
    
    // 存在漏洞的存储方法
    void saveData(CrawledData data) throws SQLException {
        Statement stmt = connection.createStatement();
        // 漏洞点：直接拼接不可信数据
        String sql = String.format(
            "INSERT INTO pages(url, content) VALUES('%s', '%s')",
            data.url, 
            data.content.replace("'", "''") // 错误的转义方式
        );
        stmt.executeUpdate(sql);
    }
    
    void close() throws SQLException {
        connection.close();
    }
}

// 爬虫核心引擎
class WebCrawler {
    private DataStorage storage;
    
    WebCrawler(DataStorage storage) {
        this.storage = storage;
    }
    
    void crawl(String url) {
        // 模拟抓取过程
        String maliciousContent = 
            "Hacked Content'); DROP TABLE pages;-- ";
        
        try {
            storage.saveData(new CrawledData(url, maliciousContent));
            System.out.println("Data saved successfully");
        } catch (SQLException e) {
            System.err.println("Storage failed: " + e.getMessage());
        }
    }
}

// 测试入口
public class SpiderApp {
    public static void main(String[] args) {
        try {
            CrawlerConfig config = new CrawlerConfig();
            DataStorage storage = new DataStorage(config);
            
            WebCrawler crawler = new WebCrawler(storage);
            crawler.crawl("http://example.com/?id=1");
            
            storage.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}