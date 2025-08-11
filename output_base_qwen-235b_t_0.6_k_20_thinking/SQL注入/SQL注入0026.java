import java.sql.*;
import java.io.*;

public class DataCleaner {
    public static void main(String[] args) {
        String dbURL = "jdbc:mysql://localhost:3306/test_db";
        String dbUser = "root";
        String dbPassword = "password";
        
        try (Connection conn = DriverManager.getConnection(dbURL, dbUser, dbPassword)) {
            File dataFile = new File("data.csv");
            BufferedReader reader = new BufferedReader(new FileReader(dataFile));
            String line;
            
            // 创建表（测试环境准备）
            conn.createStatement().execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), email VARCHAR(100))");
            
            // 模拟数据清洗过程
            while ((line = reader.readLine()) != null) {
                String[] fields = line.split(",");
                if (fields.length == 3) {
                    String id = fields[0];
                    String username = fields[1];
                    String email = fields[2];
                    
                    // 危险操作：直接拼接SQL语句
                    String sql = "INSERT INTO users (id, username, email) VALUES (" 
                                + id + ", '" + username + "', '" + email + "')";
                    
                    System.out.println("执行清洗SQL: " + sql);
                    conn.createStatement().executeUpdate(sql);
                }
            }
            
            reader.close();
            System.out.println("数据清洗完成！");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}