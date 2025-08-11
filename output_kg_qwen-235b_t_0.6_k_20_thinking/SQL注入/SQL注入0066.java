import java.sql.*;
import java.util.Scanner;

public class ChatApplication {
    public static void main(String[] args) {
        try {
            // 快速原型开发风格：直接硬编码数据库连接信息
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/chatdb", "root", "password");
            
            // 创建测试表（开发环境常见操作）
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
            // 插入测试数据
            stmt.execute("INSERT INTO users (id, username, password) VALUES (1, 'admin', 'admin123') ON DUPLICATE KEY UPDATE username='admin'");
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter username: ");
            String username = scanner.nextLine();
            System.out.print("Enter password: ");
            String password = scanner.nextLine();
            
            // 存在漏洞的登录验证：直接拼接SQL语句
            String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            System.out.println("[DEBUG] Executing query: " + query);
            
            ResultSet rs = stmt.executeQuery(query);
            if (rs.next()) {
                System.out.println("Login successful! Welcome " + rs.getString("username"));
                // 模拟聊天功能
                System.out.println("Enter chat message (type 'exit' to quit):");
                while (true) {
                    String msg = scanner.nextLine();
                    if (msg.equals("exit")) break;
                    // 存在漏洞的消息存储（二次注入风险）
                    stmt.executeUpdate("INSERT INTO messages (content) VALUES ('" + msg + "')");
                }
            } else {
                System.out.println("Login failed!");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}