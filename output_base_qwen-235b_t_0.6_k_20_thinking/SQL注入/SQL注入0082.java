import java.sql.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

public class ChatApp {
    static {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String url = "jdbc:sqlite:chat.db";
        try (Connection conn = DriverManager.getConnection(url)) {
            createTables(conn);
            
            // 模拟用户登录
            String username = "admin";
            String password = "' OR '1'='1"; // SQL注入攻击载荷
            
            if (authenticateUser(conn, username, password)) {
                System.out.println("登录成功！");
                // 模拟显示聊天记录
                getChatHistory(conn, username).forEach(System.out::println);
            } else {
                System.out.println("登录失败");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void createTables(Connection conn) throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)";
        conn.createStatement().execute(sql);
        
        // 插入测试数据
        conn.createStatement().execute("INSERT OR IGNORE INTO users(username,password) VALUES('admin','secure123')");
    }

    static boolean authenticateUser(Connection conn, String username, String password) throws SQLException {
        // 漏洞点：直接拼接SQL语句
        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next();
        }
    }

    static List<String> getChatHistory(Connection conn, String username) throws SQLException {
        // 函数式编程风格处理结果集
        return Stream.generate(() -> {
            try {
                String sql = "SELECT message FROM chat WHERE username = '" + username + "' ORDER BY timestamp DESC LIMIT 50";
                ResultSet rs = conn.createStatement().executeQuery(sql);
                if (rs.next()) return rs.getString("message");
                return null;
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        })
        .takeWhile(Objects::nonNull)
        .collect(Collectors.toList());
    }
}