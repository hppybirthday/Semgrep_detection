import java.sql.*;
import java.util.Scanner;

public class ChatApplication {
    public static void main(String[] args) {
        try {
            // 模拟数据库连接
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/chat_db", "root", "password");
            
            System.out.println("=== 聊天应用登录系统 ===");
            Scanner scanner = new Scanner(System.in);
            System.out.print("用户名: ");
            String username = scanner.nextLine();
            System.out.print("密码: ");
            String password = scanner.nextLine();
            
            // 存在漏洞的登录验证逻辑
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            System.out.println("[调试] 执行SQL: " + query);
            
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("登录成功! 欢迎 " + rs.getString("username"));
                // 模拟消息检索功能
                System.out.print("请输入搜索关键词: ");
                String keyword = scanner.nextLine();
                String msgQuery = "SELECT * FROM messages WHERE content LIKE '" + keyword + "%'";
                System.out.println("[调试] 执行SQL: " + msgQuery);
                ResultSet msgRs = stmt.executeQuery(msgQuery);
                while (msgRs.next()) {
                    System.out.println("[消息] " + msgRs.getString("content"));
                }
            } else {
                System.out.println("登录失败: 用户名或密码错误");
            }
            
            rs.close();
            stmt.close();
            conn.close();
            scanner.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 数据库初始化脚本（模拟）
/*
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password VARCHAR(50)
);

CREATE TABLE messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    content TEXT,
    user_id INT
);
*/