import java.sql.*;
import java.util.Scanner;

// 用户类
class User {
    String username;
    String password;
    
    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }
}

// 数据库处理类
class DatabaseHandler {
    private Connection connection;
    
    public DatabaseHandler() {
        try {
            // 使用H2内存数据库模拟
            connection = DriverManager.getConnection(
                "jdbc:h2:mem:chatdb", "sa", "");
            initializeDatabase();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    // 初始化数据库表
    private void initializeDatabase() throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
            "id INT PRIMARY KEY AUTO_INCREMENT, " +
            "username VARCHAR(50) UNIQUE, " +
            "password VARCHAR(50))");
        
        // 插入测试用户（正常情况应使用加密存储）
        try {
            stmt.execute("INSERT INTO users (username, password) " +
                "VALUES ('admin', 'admin123')");
        } catch (SQLException e) {
            // 忽略重复插入异常
        }
    }
    
    // 存在漏洞的登录验证方法
    public boolean validateUser(String username, String password) {
        String query = "SELECT * FROM users WHERE username = '" + 
            username + "' AND password = '" + password + "'";
        
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            return rs.next();
        } catch (SQLException e) {
            System.out.println("登录错误: " + e.getMessage());
            return false;
        }
    }
}

// 聊天应用主类
public class ChatApplication {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        DatabaseHandler dbHandler = new DatabaseHandler();
        
        System.out.println("=== 聊天应用登录 ===");
        System.out.print("用户名: ");
        String username = scanner.nextLine();
        
        System.out.print("密码: ");
        String password = scanner.nextLine();
        
        // 输入验证（防御式编程的表面措施）
        if (username == null || password == null || 
            username.trim().isEmpty() || password.trim().isEmpty()) {
            System.out.println("用户名和密码不能为空");
            return;
        }
        
        if (dbHandler.validateUser(username, password)) {
            System.out.println("登录成功！欢迎回来, " + username);
            // 实际应用中可能继续执行聊天逻辑
        } else {
            System.out.println("登录失败: 无效的用户名或密码");
        }
    }
}