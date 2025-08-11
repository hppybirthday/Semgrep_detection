import java.sql.*;
import java.util.function.*;

public class ChatApp {
    static {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws SQLException {
        String url = "jdbc:sqlite:chat.db";
        try (Connection conn = DriverManager.getConnection(url)) {
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
            stmt.execute("INSERT OR IGNORE INTO users (username,password) VALUES ('admin','secret')");
        }

        // 模拟登录接口
        Function<String[], Boolean> login = (credentials) -> {
            String sql = "SELECT * FROM users WHERE username = '" + credentials[0] + "' AND password = '" + credentials[1] + "'";
            try (Connection conn = DriverManager.getConnection(url);
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {
                return rs.next();
            } catch (SQLException e) {
                return false;
            }
        };

        // 测试正常登录
        System.out.println("Normal login: " + login.apply(new String[]{"admin", "secret"}));
        
        // 测试SQL注入攻击
        System.out.println("SQL Injection attack: " + login.apply(new String[]{"admin' --", "any_password"}));
    }
}