import java.sql.*;
import java.util.Scanner;

public class FileCrypt {
    private static Connection conn;

    public static void main(String[] args) {
        try {
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/filecrypt_db", "root", "password");
            Scanner scanner = new Scanner(System.in);
            
            System.out.println("=== 文件加密系统 ===");
            System.out.print("用户名: ");
            String username = scanner.nextLine();
            System.out.print("密码: ");
            String password = scanner.nextLine();
            
            if (authenticateUser(username, password)) {
                System.out.print("\
1. 加密文件 2. 解密文件 3. 退出\
选择操作: ");
                int choice = scanner.nextInt();
                scanner.nextLine(); // 清除换行符
                
                switch (choice) {
                    case 1:
                        encryptFile(scanner);
                        break;
                    case 2:
                        decryptFile(scanner);
                        break;
                    default:
                        System.out.println("退出系统");
                }
            } else {
                System.out.println("认证失败！");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean authenticateUser(String username, String password) throws SQLException {
        Statement stmt = conn.createStatement();
        // 易受攻击的SQL拼接（漏洞点）
        String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        System.out.println("执行SQL: " + query);
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }

    private static void encryptFile(Scanner scanner) throws SQLException {
        System.out.print("输入文件名: ");
        String filename = scanner.nextLine();
        System.out.print("输入加密密钥: ");
        String key = scanner.nextLine();
        
        // 存储加密元数据到数据库
        Statement stmt = conn.createStatement();
        // 漏洞扩展：恶意用户可通过filename参数注入
        String query = "INSERT INTO encrypted_files (filename, key_hash, status) VALUES ('"
                     + filename + "', SHA256('" + key + "'), 'encrypted')";
        stmt.executeUpdate(query);
        System.out.println("文件已加密存储");
    }

    private static void decryptFile(Scanner scanner) throws SQLException {
        System.out.print("输入文件名: ");
        String filename = scanner.nextLine();
        System.out.print("输入解密密钥: ");
        String key = scanner.nextLine();
        
        Statement stmt = conn.createStatement();
        // 漏洞扩展：通过filename参数注入
        String query = "SELECT * FROM encrypted_files WHERE filename='" + filename + "' AND key_hash=SHA256('" + key + "')";
        ResultSet rs = stmt.executeQuery(query);
        
        if (rs.next()) {
            System.out.println("文件解密成功");
        } else {
            System.out.println("解密失败: 文件不存在或密钥错误");
        }
    }
}