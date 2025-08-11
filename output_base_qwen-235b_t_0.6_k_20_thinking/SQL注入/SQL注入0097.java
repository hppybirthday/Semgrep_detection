import java.sql.*;
import java.util.*;

// 领域模型
class WebPage {
    private String url;
    private String title;
    private String content;

    public WebPage(String url, String title, String content) {
        this.url = url;
        this.title = title;
        this.content = content;
    }

    // Getters
    public String getUrl() { return url; }
    public String getTitle() { return title; }
    public String getContent() { return content; }
}

// 仓储接口
interface PageRepository {
    void save(WebPage page);
}

// 基础设施层 - 漏洞实现
class JdbcPageRepository implements PageRepository {
    private Connection connection;

    public JdbcPageRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public void save(WebPage page) {
        try {
            // 漏洞点：直接拼接SQL
            String query = "INSERT INTO pages (url, title, content) VALUES ('" 
                + page.getUrl() + "', '" 
                + page.getTitle() + "', '" 
                + page.getContent() + "')";
            
            Statement stmt = connection.createStatement();
            stmt.executeUpdate(query);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

// 应用服务
class CrawlerService {
    private PageRepository repository;

    public CrawlerService(PageRepository repository) {
        this.repository = repository;
    }

    public void processPage(String url, String title, String content) {
        WebPage page = new WebPage(url, title, content);
        repository.save(page);
    }
}

// 模拟爬虫入口
public class VulnerableCrawler {
    public static void main(String[] args) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/crawler_db", "user", "password");
            
            PageRepository repo = new JdbcPageRepository(conn);
            CrawlerService service = new CrawlerService(repo);
            
            // 模拟处理用户输入
            System.out.println("Processing malicious input...");
            String maliciousTitle = "test'; DROP TABLE pages;--";
            service.processPage("http://example.com", maliciousTitle, "malicious content");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}