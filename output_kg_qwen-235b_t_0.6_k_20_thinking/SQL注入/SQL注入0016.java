import java.sql.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class FileCryptoTool {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/file_crypto";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    public static void main(String[] args) {
        try {
            if (args.length < 3) {
                System.out.println("Usage: java FileCryptoTool <encrypt|decrypt> <filename> <password>");
                return;
            }

            String operation = args[0];
            String filename = args[1];
            String password = args[2];

            if (operation.equals("encrypt")) {
                encryptFile(filename, password);
            } else if (operation.equals("decrypt")) {
                decryptFile(filename, password);
            } else {
                System.out.println("Invalid operation. Use 'encrypt' or 'decrypt'");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encryptFile(String filename, String password) throws Exception {
        // 漏洞点：直接拼接SQL语句
        String sql = String.format("SELECT * FROM encryption_keys WHERE filename = '%s' AND password = '%s'", 
            filename, password);

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                System.out.println("File already encrypted");
                return;
            }
        }

        // 模拟加密过程
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        // 模拟写入加密记录
        String insertSql = String.format("INSERT INTO encryption_keys (filename, password, encrypted_path) VALUES ('%s', '%s', '%s_enc')",
            filename, password, filename);
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            stmt.executeUpdate(insertSql);
        }
        
        System.out.println("File encrypted successfully");
    }

    private static void decryptFile(String filename, String password) throws Exception {
        // 漏洞点：直接拼接SQL语句
        String sql = String.format("SELECT * FROM encryption_keys WHERE filename = '%s' AND password = '%s'", 
            filename, password);

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (!rs.next()) {
                System.out.println("No encryption record found");
                return;
            }

            // 模拟解密过程
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            
            System.out.println("File decrypted successfully");
        }
    }
}