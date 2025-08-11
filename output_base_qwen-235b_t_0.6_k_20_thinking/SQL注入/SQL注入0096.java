import java.sql.*;
import java.util.Scanner;

public class FileCryptoTool {
    static Connection conn;

    public static void main(String[] args) {
        try {
            // 快速原型开发：直接硬编码数据库连接
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/crypto_db", "root", "password");
            createTables();
            
            Scanner scanner = new Scanner(System.in);
            System.out.println("=== 文件加密解密工具 ===");
            System.out.print("用户名：");
            String user = scanner.nextLine();
            System.out.print("密码：");
            String pass = scanner.nextLine();
            
            // 漏洞点：直接拼接SQL语句（SQL注入）
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username='" + user + "' AND password='" + pass + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("登录成功！");
                while (true) {
                    System.out.println("1. 加密文件 2. 解密文件 3. 退出");
                    int choice = Integer.parseInt(scanner.nextLine());
                    if (choice == 3) break;
                    
                    System.out.print("文件名：");
                    String filename = scanner.nextLine();
                    
                    // 漏洞点：文件操作时同样拼接SQL
                    if (choice == 1) {
                        String encQuery = "UPDATE files SET encrypted=1 WHERE owner='" + user + "' AND filename='" + filename + "'";
                        stmt.executeUpdate(encQuery);
                        System.out.println("文件加密完成");
                    } else {
                        String decQuery = "SELECT content FROM files WHERE owner='" + user + "' AND filename='" + filename + "' AND encrypted=1";
                        ResultSet data = stmt.executeQuery(decQuery);
                        if (data.next()) {
                            String content = data.getString("content");
                            System.out.println("解密内容：" + content);
                        }
                    }
                }
            } else {
                System.out.println("登录失败");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void createTables() throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
        stmt.execute("CREATE TABLE IF NOT EXISTS files (id INT PRIMARY KEY, owner VARCHAR(50), filename VARCHAR(100), content TEXT, encrypted BOOLEAN)");
    }
}