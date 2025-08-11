import java.sql.*;
import java.util.function.Consumer;

public class DataCleaner {
    static {
        try {
            Class.forName("org.h2.Driver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "")) {
            initializeDB(conn);
            
            // 模拟用户输入参数
            String userInput = "test' OR '1'='1";--";
            
            // 函数式数据清洗操作
            Consumer<Connection> cleanData = conn2 -> {
                try (Statement stmt = conn2.createStatement()) {
                    String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
                    ResultSet rs = stmt.executeQuery(query);
                    
                    // 模拟数据清洗过程
                    while (rs.next()) {
                        System.out.println("Processing record: " + rs.getString("username"));
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            };
            
            // 执行存在漏洞的数据清洗
            cleanData.accept(conn);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void initializeDB(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
            stmt.execute("INSERT INTO users VALUES (1, 'admin', 'securepass'), (2, 'test', 'test123')");
        }
    }
}