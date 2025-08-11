import java.sql.*;
import java.util.Scanner;

public class FileCryptoTool {
    private static Connection conn;

    public static void main(String[] args) {
        try {
            // 初始化数据库连接
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/filecrypto", "root", "password");
            createTable();
            
            Scanner scanner = new Scanner(System.in);
            System.out.println("=== 文件加密解密工具 ===");
            System.out.print("请输入操作类型 (encrypt/decrypt): ");
            String action = scanner.nextLine();
            
            System.out.print("请输入文件名: ");
            String filename = scanner.nextLine();
            
            if (action.equals("encrypt")) {
                encryptFile(filename);
            } else if (action.equals("decrypt")) {
                decryptFile(filename);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void createTable() throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS files (id INT PRIMARY KEY AUTO_INCREMENT, 
            filename VARCHAR(255), encrypted_path VARCHAR(255), is_encrypted BOOLEAN)");
    }

    private static void encryptFile(String filename) throws SQLException {
        Statement stmt = conn.createStatement();
        // 漏洞点：直接拼接用户输入
        ResultSet rs = stmt.executeQuery("SELECT * FROM files WHERE filename = '" + filename + "' AND is_encrypted = false");
        
        if (rs.next()) {
            String encryptedPath = "/encrypted/" + rs.getString("id") + ".enc";
            // 模拟加密操作
            System.out.println("[+] 文件已加密: " + encryptedPath);
            
            // 更新数据库
            stmt.executeUpdate("UPDATE files SET encrypted_path = '" + encryptedPath + "', 
                is_encrypted = true WHERE id = " + rs.getInt("id"));
        } else {
            System.out.println("[-] 文件未找到或已加密");
        }
    }

    private static void decryptFile(String filename) throws SQLException {
        Statement stmt = conn.createStatement();
        // 漏洞点：直接拼接用户输入
        ResultSet rs = stmt.executeQuery("SELECT * FROM files WHERE filename = '" + filename + "' AND is_encrypted = true");
        
        if (rs.next()) {
            String decryptedPath = rs.getString("encrypted_path").replace(".enc", "");
            // 模拟解密操作
            System.out.println("[+] 文件已解密: " + decryptedPath);
            
            // 更新数据库
            stmt.executeUpdate("UPDATE files SET encrypted_path = NULL, 
                is_encrypted = false WHERE id = " + rs.getInt("id"));
        } else {
            System.out.println("[-] 文件未找到或未加密");
        }
    }
}