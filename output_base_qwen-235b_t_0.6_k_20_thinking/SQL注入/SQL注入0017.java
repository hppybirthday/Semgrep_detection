import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 领域模型
class CrawledData {
    private String url;
    private String content;
    
    public CrawledData(String url, String content) {
        this.url = url;
        this.content = content;
    }
    
    public String getUrl() { return url; }
    public String getContent() { return content; }
}

// 仓储接口
interface CrawledDataRepository {
    void save(CrawledData data) throws SQLException;
    List<CrawledData> findAll() throws SQLException;
}

// 漏洞实现
class JdbcCrawledDataRepository implements CrawledDataRepository {
    private Connection connection;
    
    public JdbcCrawledDataRepository(String dbUrl) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl);
        createTable();
    }
    
    private void createTable() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS crawled_data (id INT PRIMARY KEY AUTO_INCREMENT, url VARCHAR(255), content TEXT)");
        }
    }
    
    @Override
    public void save(CrawledData data) throws SQLException {
        // 漏洞点：直接拼接SQL字符串
        String sql = "INSERT INTO crawled_data (url, content) VALUES ('" 
                   + data.getUrl() + "', '" 
                   + data.getContent() + "')";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }
    
    @Override
    public List<CrawledData> findAll() throws SQLException {
        List<CrawledData> results = new ArrayList<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM crawled_data")) {
            
            while (rs.next()) {
                results.add(new CrawledData(
                    rs.getString("url"),
                    rs.getString("content")
                ));
            }
        }
        return results;
    }
}

// 应用服务
class CrawlerService {
    private CrawledDataRepository repository;
    
    public CrawlerService(CrawledDataRepository repository) {
        this.repository = repository;
    }
    
    public void processPage(String url, String content) {
        try {
            repository.save(new CrawledData(url, content));
        } catch (SQLException e) {
            System.err.println("保存数据失败: " + e.getMessage());
        }
    }
}

// 测试类
public class SqlInjectionDemo {
    public static void main(String[] args) {
        try {
            // 初始化数据库连接
            CrawledDataRepository repo = new JdbcCrawledDataRepository("jdbc:mysql://localhost/testdb");
            CrawlerService crawler = new CrawlerService(repo);
            
            // 模拟正常爬取
            crawler.processPage("http://example.com", "正常内容");
            
            // 漏洞触发示例 - SQL注入攻击
            String maliciousContent = "恶意内容'); DROP TABLE crawled_data;-- ";
            crawler.processPage("http://malicious.com", maliciousContent);
            
            // 查询验证
            System.out.println("当前数据库内容:");
            for (CrawledData data : repo.findAll()) {
                System.out.println("URL: " + data.getUrl() + ", 内容: " + data.getContent());
            }
            
        } catch (SQLException e) {
            System.err.println("数据库错误: " + e.getMessage());
        }
    }
}