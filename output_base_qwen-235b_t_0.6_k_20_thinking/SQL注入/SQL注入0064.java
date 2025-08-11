import java.sql.*;
import java.util.Scanner;

public class FileCryptoTool {
    private static final String DB_URL = "jdbc:h2:mem:test";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";

    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            setupDatabase(conn);
            Scanner scanner = new Scanner(System.in);
            System.out.println("=== 文件加密解密工具 ===");
            System.out.print("用户名: ");
            String username = scanner.nextLine();
            System.out.print("密码: ");
            String password = scanner.nextLine();

            if (authenticateUser(conn, username, password)) {
                System.out.println("登录成功!");
                // 模拟加密解密功能
                System.out.println("功能待实现: 加密/解密文件操作");
            } else {
                System.out.println("登录失败");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void setupDatabase(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
            // 插入测试数据
            stmt.execute("INSERT INTO users (id, username, password) VALUES (1, 'admin', 'secure123')" + 
                         "ON CONFLICT DO NOTHING");
        }
    }

    private static boolean authenticateUser(Connection conn, String username, String password) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next();
        }
    }
}