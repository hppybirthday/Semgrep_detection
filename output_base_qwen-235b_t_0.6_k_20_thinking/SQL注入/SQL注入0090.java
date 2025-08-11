import java.sql.*;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) {
        String url = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
        String user = "sa";
        String password = "";
        
        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            // 创建测试表
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE TABLE customer_data (id INT PRIMARY KEY, name VARCHAR(100), phone VARCHAR(20))");
                // 插入测试数据
                stmt.execute("INSERT INTO customer_data VALUES (1, 'John Doe', '123-456-7890'), (2, 'Jane Smith', '987-654-3210')");
            }
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("输入要清洗的表名（如customer_data）：");
            String tableName = scanner.nextLine();
            System.out.print("输入要清洗的字段名（如phone）：");
            String columnName = scanner.nextLine();
            System.out.print("输入正则表达式替换规则（如-|\\s: "");
            String regex = scanner.nextLine();
            
            // 漏洞点：直接拼接用户输入到SQL语句中
            String sql = String.format(
                "UPDATE %s SET %s = REGEXP_REPLACE(%s, '%s', '')",
                tableName, columnName, columnName, regex
            );
            
            try (Statement stmt = conn.createStatement()) {
                int rowsAffected = stmt.executeUpdate(sql);
                System.out.println("清洗完成，影响记录数：" + rowsAffected);
                
                // 显示清洗结果
                ResultSet rs = stmt.executeQuery("SELECT * FROM " + tableName);
                while (rs.next()) {
                    System.out.println(String.format("ID: %d, Name: %s, Phone: %s",
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("phone")
                    ));
                }
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}