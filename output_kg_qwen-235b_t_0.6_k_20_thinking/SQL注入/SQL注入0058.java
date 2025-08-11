import java.sql.*;
import java.io.*;

public class DataCleaner {
    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/data_cleaning?useSSL=false";
        String user = "root";
        String password = "password";
        
        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement()) {
            
            BufferedReader reader = new BufferedReader(new FileReader("data.csv"));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] data = line.split(",");
                String name = data[0];
                String email = data[1];
                
                // 漏洞点：直接拼接SQL语句
                String sql = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')";
                stmt.executeUpdate(sql);
            }
            System.out.println("数据导入完成");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}