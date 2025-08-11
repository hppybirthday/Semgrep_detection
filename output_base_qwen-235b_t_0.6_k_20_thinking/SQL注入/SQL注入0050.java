import java.sql.*;
import java.util.Scanner;

public class ChatApp {
    public static void main(String[] args) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:chatdb", "sa", "");
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
            stmt.execute("CREATE TABLE IF NOT EXISTS messages (id INT PRIMARY KEY, username VARCHAR(50), message TEXT)");
            
            // 模拟用户注册
            stmt.execute("INSERT INTO users (id, username, password) VALUES (1, 'admin', 'admin123')");
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("用户名: ");
            String user = scanner.nextLine();
            System.out.print("密码: ");
            String pass = scanner.nextLine();
            
            // 存在漏洞的登录验证
            String query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("登录成功! " + user);
                System.out.print("发送消息: ");
                String msg = scanner.nextLine();
                
                // 存在漏洞的消息存储
                String insert = "INSERT INTO messages (id, username, message) VALUES (" 
                    + "NEXT VALUE FOR SYSTEM_SEQUENCE_H2_TEST, '" 
                    + user + "', '" 
                    + msg + "')";
                stmt.executeUpdate(insert);
                System.out.println("消息已发送");
            } else {
                System.out.println("登录失败");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}