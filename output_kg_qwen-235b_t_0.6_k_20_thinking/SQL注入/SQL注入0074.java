import java.sql.*;
import java.util.regex.*;

// 数据清洗工具类（防御式编程）
public class DataCleaner {
    // 简单的输入清洗方法（存在缺陷）
    public static String cleanInput(String input) {
        if (input == null) return "";
        // 试图过滤特殊字符
        return input.replaceAll("[;'"]", "");
    }

    // SQL注入漏洞演示类
    public static void main(String[] args) {
        String username = "admin";
        String userInput = "test'; DROP TABLE users;--"; // 恶意输入
        
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/testdb", "root", "password");
            
            // 危险的SQL拼接
            String query = "SELECT * FROM users WHERE username = '" 
                + cleanInput(username) + "' AND password = '" 
                + cleanInput(userInput) + "'";
            
            System.out.println("执行查询: " + query);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("登录成功: " + rs.getString("username"));
            } else {
                System.out.println("登录失败");
            }
            
        } catch (SQLException e) {
            System.out.println("数据库错误: " + e.getMessage());
        }
    }
}

// 用户实体类
class User {
    private String username;
    private String password;
    
    public User(String username, String password) {
        this.username = DataCleaner.cleanInput(username);
        this.password = DataCleaner.cleanInput(password);
    }
    
    // 模拟数据访问层
    public boolean authenticate() {
        String sql = String.format(
            "SELECT * FROM users WHERE username='%s' AND password='%s'",
            this.username, this.password
        );
        
        // 模拟数据库执行
        System.out.println("执行SQL: " + sql);
        // 实际应使用PreparedStatement
        return sql.contains("DROP TABLE"); // 模拟攻击成功
    }
}