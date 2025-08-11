import java.sql.*;
import java.util.Scanner;
import java.util.Base64;

public class FileEncryptor {
    private static Connection conn;

    public static void main(String[] args) {
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/filedb", "root", "password");
            Scanner scanner = new Scanner(System.in);
            
            System.out.print("用户名: ");
            String user = scanner.nextLine();
            System.out.print("密码: ");
            String pass = scanner.nextLine();
            
            if (authenticate(user, pass)) {
                System.out.print("文件名: ");
                String filename = scanner.nextLine();
                System.out.print("文件内容: ");
                String content = scanner.nextLine();
                
                String encrypted = Base64.getEncoder().encodeToString(content.getBytes());
                saveFile(filename, encrypted);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static boolean authenticate(String user, String pass) throws SQLException {
        // 存在SQL注入漏洞的认证查询
        String query = "SELECT * FROM users WHERE username='" + user + "' AND password='" + pass + "'";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            return rs.next();
        }
    }

    static void saveFile(String filename, String content) throws SQLException {
        // 存在SQL注入漏洞的文件存储操作
        String query = "INSERT INTO files (filename, content) VALUES ('" + filename + "', '" + content + "')";
        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(query);
            System.out.println("文件保存成功");
        }
    }
}