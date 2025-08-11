import java.sql.*;
import java.io.*;

public class DataCleaner {
    public static void main(String[] args) {
        String dbURL = "jdbc:mysql://localhost:3306/datacleaner";
        String dbUser = "root";
        String dbPassword = "password";

        try (Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword)) {
            // 创建原始数据表
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE TABLE IF NOT EXISTS raw_data (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(255), email VARCHAR(255))");
            }

            // 模拟数据清洗流程
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("请输入清洗后的数据 (格式: 姓名,email)");
            
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.equalsIgnoreCase("exit")) break;
                
                // 简单的数据清洗逻辑
                String[] parts = line.split(",");
                if (parts.length != 2) {
                    System.out.println("格式错误，请使用 姓名,email 格式");
                    continue;
                }
                
                String cleanedName = cleanInput(parts[0].trim());
                String cleanedEmail = cleanInput(parts[1].trim());
                
                // 存在SQL注入漏洞的代码
                String sql = "INSERT INTO raw_data (name, email) VALUES ('"
                          + cleanedName + "', '" + cleanedEmail + "')";
                
                try (Statement stmt = conn.createStatement()) {
                    stmt.executeUpdate(sql);
                    System.out.println("数据插入成功");
                } catch (SQLException e) {
                    System.out.println("数据插入失败: " + e.getMessage());
                }
            }
            
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }
    
    // 简单的清洗函数（错误示范）
    private static String cleanInput(String input) {
        // 仅做简单空格清理，未处理特殊字符
        return input.replaceAll("\\\\s+", " ");
    }
}