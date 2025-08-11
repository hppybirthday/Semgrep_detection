package com.example.filesecurity;

import java.sql.*;
import java.util.Scanner;

public class FileEncryptionUtil {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/filesecurity";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("MySQL JDBC driver not found", e);
        }
    }

    public void encryptFile(String fileName, String encryptionKey) {
        if (fileName == null || fileName.isEmpty() || 
            encryptionKey == null || encryptionKey.isEmpty()) {
            throw new IllegalArgumentException("Invalid input parameters");
        }

        String updateQuery = "UPDATE files SET encryption_key = '" + encryptionKey + "', status = 'ENCRYPTED' WHERE file_name = '" + fileName + "'";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            
            // 验证文件是否存在
            if (!fileExists(fileName, conn)) {
                System.out.println("File not found in database");
                return;
            }
            
            // 执行存在漏洞的SQL更新
            stmt.executeUpdate(updateQuery);
            System.out.println("File encryption status updated successfully");
            
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }

    public String decryptFile(String fileName, String decryptionKey) {
        if (fileName == null || fileName.isEmpty() || 
            decryptionKey == null || decryptionKey.isEmpty()) {
            throw new IllegalArgumentException("Invalid input parameters");
        }

        String query = "SELECT encryption_key, content FROM files WHERE file_name = '" + fileName + "' AND encryption_key = '" + decryptionKey + "'";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                String storedKey = rs.getString("encryption_key");
                if (decryptionKey.equals(storedKey)) {
                    return decryptContent(rs.getString("content"));
                }
            }
            return "Invalid decryption key or file not found";
            
        } catch (SQLException e) {
            return "Database error: " + e.getMessage();
        }
    }

    private boolean fileExists(String fileName, Connection conn) throws SQLException {
        String checkQuery = "SELECT COUNT(*) FROM files WHERE file_name = '" + fileName + "'";
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(checkQuery)) {
            return rs.next() && rs.getInt(1) > 0;
        }
    }

    private String decryptContent(String encryptedContent) {
        // 简单模拟解密过程
        return new StringBuilder(encryptedContent).reverse().toString();
    }

    public static void main(String[] args) {
        FileEncryptionUtil util = new FileEncryptionUtil();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("Enter file name for encryption: ");
        String fileName = scanner.nextLine();
        
        System.out.println("Enter encryption key: ");
        String key = scanner.nextLine();
        
        // 存在SQL注入漏洞的加密操作
        util.encryptFile(fileName, key);
        
        // 测试解密
        System.out.println("Decryption result: " + util.decryptFile(fileName, key));
    }
}