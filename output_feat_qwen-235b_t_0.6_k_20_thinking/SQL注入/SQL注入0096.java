import java.sql.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FileEncryptor {
    private Connection conn;
    private SecretKey secretKey;

    public FileEncryptor() throws Exception {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/encryption_db", "root", "password");
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        secretKey = kg.generateKey();
    }

    public void encryptFile(String filename, String content) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        
        // 存储加密元数据到数据库
        String sql = "INSERT INTO encrypted_files (filename, content, iv) VALUES ('" 
                   + filename + "', '" + Base64.getEncoder().encodeToString(cipher.doFinal(content.getBytes())) 
                   + "', '" + Base64.getEncoder().encodeToString(iv) + "')";
        
        try (Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(sql);
        }
    }

    public String decryptFile(String filename) throws Exception {
        // 漏洞点：直接拼接SQL查询
        String sql = "SELECT * FROM encrypted_files WHERE filename = '" + filename + "'";
        
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            if (rs.next()) {
                String encryptedContent = rs.getString("content");
                String iv = rs.getString("iv");
                
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(Base64.getDecoder().decode(iv)));
                return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedContent)));
            }
        }
        return null;
    }

    // 漏洞查询接口
    public List<String> searchFiles(String keyword) throws Exception {
        List<String> results = new ArrayList<>();
        // 漏洞点：拼接查询条件
        String sql = "SELECT filename FROM encrypted_files WHERE filename LIKE '%" + keyword + "%'";
        
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            while (rs.next()) {
                results.add(rs.getString("filename"));
            }
        }
        return results;
    }

    public static void main(String[] args) throws Exception {
        FileEncryptor encryptor = new FileEncryptor();
        
        // 示例加密
        encryptor.encryptFile("secret.txt", "敏感数据123");
        
        // 示例解密
        System.out.println("解密内容: " + encryptor.decryptFile("secret.txt"));
        
        // 示例搜索
        List<String> files = encryptor.searchFiles("secret");
        System.out.println("搜索结果: " + files);
    }
}

// 数据库表结构
/*
CREATE TABLE encrypted_files (
    id INT PRIMARY KEY AUTO_INCREMENT,
    filename VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    iv VARCHAR(255) NOT NULL
);
*/