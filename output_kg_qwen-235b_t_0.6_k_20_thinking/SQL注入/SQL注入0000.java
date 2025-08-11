import java.sql.*;
import java.util.Scanner;

// 文件信息实体类
class EncryptedFile {
    int id;
    String name;
    String encryptedKey;
    String algorithm;
    
    public EncryptedFile(int id, String name, String encryptedKey, String algorithm) {
        this.id = id;
        this.name = name;
        this.encryptedKey = encryptedKey;
        this.algorithm = algorithm;
    }
}

// 数据库操作类
class FileDAO {
    Connection getConnection() throws SQLException {
        try {
            Class.forName("org.h2.Driver");
            return DriverManager.getConnection(
                "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");
        } catch (ClassNotFoundException e) {
            throw new SQLException("H2驱动未找到", e);
        }
    }

    void initDB() throws SQLException {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS files (id INT PRIMARY KEY AUTO_INCREMENT, " +
                          "name VARCHAR(255), encrypted_key VARCHAR(255), algorithm VARCHAR(50))");
            // 插入测试数据
            stmt.execute("INSERT INTO files(name, encrypted_key, algorithm) " +
                          "SELECT 'secret.txt', 'AES256', 'AES' WHERE NOT EXISTS(SELECT 1 FROM files)");
        }
    }

    // 存在SQL注入漏洞的查询方法
    EncryptedFile findFileByName(String fileName) throws SQLException {
        String query = "SELECT * FROM files WHERE name = '" + fileName + "'";
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return new EncryptedFile(
                    rs.getInt("id"),
                    rs.getString("name"),
                    rs.getString("encrypted_key"),
                    rs.getString("algorithm")
                );
            }
            return null;
        }
    }
}

// 文件加密工具主类
public class FileEncryptionTool {
    public static void main(String[] args) {
        try {
            FileDAO fileDAO = new FileDAO();
            fileDAO.initDB();
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("请输入要解密的文件名：");
            String fileName = scanner.nextLine();
            
            EncryptedFile file = fileDAO.findFileByName(fileName);
            
            if (file != null) {
                System.out.println("找到加密文件：" + file.name);
                System.out.println("使用密钥：" + file.encryptedKey);
                System.out.println("加密算法：" + file.algorithm);
                // 实际解密逻辑...
            } else {
                System.out.println("未找到文件！");
            }
        } catch (SQLException e) {
            System.err.println("数据库错误：" + e.getMessage());
        }
    }
}