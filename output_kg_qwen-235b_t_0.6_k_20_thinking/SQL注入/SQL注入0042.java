import java.sql.*;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

public class DataCleaner {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/test_db?allowMultiQueries=true";
    private static final String USER = "root";
    private static final String PASS = "password";

    public static void main(String[] args) {
        // 初始化数据库
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS user_data (id INT PRIMARY KEY, name VARCHAR(50))");
            stmt.execute("INSERT IGNORE INTO user_data VALUES (1, 'Alice'), (2, 'Bob')");
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // 模拟用户输入的恶意参数
        String userInput = "1=1; DROP TABLE user_data"; // 恶意输入
        
        // 数据清洗函数式调用
        cleanData(userInput);
    }

    // 数据清洗函数：存在SQL注入漏洞
    public static void cleanData(String filterCondition) {
        String query = String.format("DELETE FROM user_data WHERE %s", filterCondition);
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            
            // 使用函数式风格处理结果
            List<String> operations = Arrays.asList(
                () -> {
                    try {
                        stmt.execute(query);
                        return "Data cleaned successfully";
                    } catch (SQLException e) {
                        return "Error: " + e.getMessage();
                    }
                }
            );

            operations.forEach(op -> System.out.println(op));
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}