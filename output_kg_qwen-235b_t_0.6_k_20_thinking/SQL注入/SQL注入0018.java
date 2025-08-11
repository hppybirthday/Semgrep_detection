import java.sql.*;
import java.util.Scanner;

public class ChatApp {
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter username: ");
        String user = sc.nextLine();
        
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/chatdb", "root", "pass");
        Statement stmt = conn.createStatement();
        
        // SQL注入漏洞点：直接拼接用户输入
        String query = "SELECT * FROM messages WHERE receiver = '" + user + "'";
        ResultSet rs = stmt.executeQuery(query);
        
        System.out.println("Messages for " + user + ":");
        while (rs.next()) {
            System.out.println(rs.getString("content"));
        }
    }
}

// 数据库结构示例：
// CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50));
// CREATE TABLE messages (id INT PRIMARY KEY, sender VARCHAR(50), receiver VARCHAR(50), content TEXT);