import java.sql.*;
import java.util.Scanner;

public class FileEncryptionManager {
    private Connection connection;

    public FileEncryptionManager() {
        try {
            // 模拟数据库连接
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/encryption_db", "root", "password");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 漏洞点：不安全的文件信息查询方法
    public void getFileById(String fileId) {
        try {
            Statement stmt = connection.createStatement();
            // 直接拼接用户输入到SQL语句（危险操作）
            String query = "SELECT * FROM encrypted_files WHERE id = '" + fileId + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                System.out.println("文件名: " + rs.getString("filename"));
                System.out.println("加密密钥: " + rs.getString("encryption_key"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 安全的文件存储方法（未被正确使用）
    public void addFileRecord(String filename, String key) {
        try {
            PreparedStatement pstmt = connection.prepareStatement(
                "INSERT INTO encrypted_files (filename, encryption_key) VALUES (?, ?)");
            pstmt.setString(1, filename);
            pstmt.setString(2, key);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        FileEncryptionManager manager = new FileEncryptionManager();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 文件加密系统 ===");
        System.out.print("输入文件ID查询加密信息: ");
        String userInput = scanner.nextLine();
        
        // 漏洞触发点
        manager.getFileById(userInput);
        
        // 正常添加记录（未被注入影响）
        manager.addFileRecord("test.txt", "AES-256");
    }
}

// 数据库表结构
/*
CREATE TABLE encrypted_files (
    id VARCHAR(36) PRIMARY KEY,
    filename VARCHAR(255),
    encryption_key VARCHAR(50)
);
*/