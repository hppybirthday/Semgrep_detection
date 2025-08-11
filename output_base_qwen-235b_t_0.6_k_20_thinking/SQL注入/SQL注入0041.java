import java.io.*;
import java.sql.*;

public class DataProcessor {
    public static void main(String[] args) {
        String dbUrl = "jdbc:mysql://localhost:3306/bigdata_db";
        String user = "admin";
        String password = "secure123";
        
        try (Connection conn = DriverManager.getConnection(dbUrl, user, password);
             BufferedReader br = new BufferedReader(new FileReader("userdata.csv"))) {
            
            String line;
            Statement stmt = conn.createStatement();
            
            while ((line = br.readLine()) != null) {
                String[] data = line.split(",");
                String username = data[0];
                String email = data[1];
                int age = Integer.parseInt(data[2]);
                
                // 漏洞点：直接拼接SQL语句
                String sql = "INSERT INTO users (username, email, age) VALUES ('" 
                           + username + "', '" + email + "', " + age + ")";
                
                System.out.println("Executing: " + sql);
                stmt.executeUpdate(sql);
            }
            
            stmt.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/*
CSV文件示例：
john_doe,john@example.com,30
malicious_user@','malicious@example.com',1); DROP TABLE users;--,
*/