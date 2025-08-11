import java.sql.*;
import java.util.Scanner;

public class WebCrawler {
    private static Connection connection;

    static {
        try {
            // 声明式配置数据库连接
            String url = "jdbc:mysql://localhost:3306/crawler_db";
            String user = "root";
            String password = "secure123";
            connection = DriverManager.getConnection(url, user, password);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter search keyword: ");
        String keyword = scanner.nextLine();
        
        // 模拟爬虫搜索操作
        String url = "https://example.com/search?q=" + keyword;
        String content = fetchWebContent(url);
        
        // 存储爬取结果（存在漏洞）
        saveResult(keyword, content);
    }

    private static String fetchWebContent(String url) {
        // 模拟爬虫抓取过程
        return "Mock content for: " + url;
    }

    private static void saveResult(String keyword, String content) {
        try {
            // 危险的SQL拼接操作
            Statement statement = connection.createStatement();
            String sql = "INSERT INTO search_results (keyword, content) VALUES ('"
                     + keyword + "', '" + content + "')";
            
            System.out.println("Executing SQL: " + sql);
            statement.executeUpdate(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 初始化表结构
    public static void initDatabase() {
        try {
            Statement statement = connection.createStatement();
            statement.execute("CREATE TABLE IF NOT EXISTS search_results ("
                     + "id INT PRIMARY KEY AUTO_INCREMENT, "
                     + "keyword VARCHAR(255), "
                     + "content TEXT)");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}