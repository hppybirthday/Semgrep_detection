import java.sql.*;
import java.util.Scanner;

public class FileEncryptor {
    private static Connection conn;

    public static void main(String[] args) {
        try {
            // 模拟数据库连接
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/file_security", "root", "password");
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("用户名: ");
            String username = scanner.nextLine();
            System.out.print("密码: ");
            String password = scanner.nextLine();
            
            // 漏洞点：直接拼接SQL语句
            String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("登录成功! 欢迎 " + rs.getString("username"));
                System.out.print("请输入要解密的文件ID: ");
                String fileId = scanner.nextLine();
                
                // 第二个漏洞点：文件ID参数拼接
                String fileQuery = "SELECT path FROM files WHERE id=" + fileId;
                Statement fileStmt = conn.createStatement();
                ResultSet fileRs = fileStmt.executeQuery(fileQuery);
                
                if (fileRs.next()) {
                    System.out.println("正在解密文件: " + fileRs.getString("path"));
                    // 模拟解密操作
                    decryptFile(fileRs.getString("path"));
                } else {
                    System.out.println("文件不存在");
                }
            } else {
                System.out.println("登录失败");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void decryptFile(String path) {
        // 模拟解密过程
        System.out.println("[解密引擎] 正在处理文件: " + path);
        System.out.println("解密完成，文件保存至: " + path.replace(".enc", ""));
    }
}