package chat.app;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class ChatService {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/chatdb";
    private static final String USER = "root";
    private static final String PASS = "password";

    public List<String> searchMessages(String username, String keyword) {
        List<String> results = new ArrayList<>();
        String query = "SELECT content FROM messages WHERE username = '" 
                     + username + "' AND content LIKE '%" 
                     + keyword + "%'";

        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {

            Function<ResultSet, String> extractContent = rs -> {
                try {
                    return rs.getString("content");
                } catch (SQLException e) {
                    throw new RuntimeException(e);
                }
            };

            while (rs.next()) {
                results.add(extractContent.apply(rs));
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return results;
    }

    public void addMessage(String username, String content) {
        String query = "INSERT INTO messages (username, content, timestamp) VALUES ('"
                     + username + "', '" + content + "', NOW())";

        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {

            stmt.executeUpdate(query);

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        ChatService chat = new ChatService();
        
        // 模拟用户输入
        String userInputUser = "admin";
        String userInputKeyword = "test";
        
        // 正常使用示例
        System.out.println("Normal search:");
        chat.searchMessages(userInputUser, userInputKeyword).forEach(System.out::println);
        
        // 恶意输入示例
        System.out.println("\
Malicious input attempt:");
        String maliciousUser = "admin' OR '1'='1";
        String maliciousKeyword = "' OR '1'='1";
        chat.searchMessages(maliciousUser, maliciousKeyword).forEach(System.out::println);
        
        // 演示添加消息
        chat.addMessage("testuser", "Hello World");
    }
}