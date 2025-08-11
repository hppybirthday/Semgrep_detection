import java.sql.*;
import java.util.Scanner;

public class LoginActivity {
    public static void main(String[] args) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:sqlite:mobile_app.db");
            Statement stmt = conn.createStatement();
            
            // 创建测试表（模拟注册流程）
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
            stmt.execute("INSERT OR IGNORE INTO users (username,password) VALUES ('admin','securePass123')");
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter username: ");
            String username = scanner.nextLine();
            System.out.print("Enter password: ");
            String password = scanner.nextLine();
            
            // 漏洞点：直接拼接用户输入到SQL查询
            String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            System.out.println("[DEBUG] Executing query: " + query);
            
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("Login successful! Welcome " + rs.getString("username"));
                // 模拟敏感操作
                if(rs.getString("username").equals("admin")) {
                    System.out.println("[ADMIN] Accessing sensitive data...");
                }
            } else {
                System.out.println("Invalid credentials");
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (Exception e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }
}