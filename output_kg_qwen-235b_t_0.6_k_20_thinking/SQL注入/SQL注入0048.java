import java.sql.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/encryptdb", "root", "password");
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter username: ");
            String user = scanner.nextLine();
            System.out.print("Enter password: ");
            String pass = scanner.nextLine();
            
            // Vulnerable SQL query (login bypass)
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username='" + user + 
                          "' AND password='" + pass + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("Login successful!");
                System.out.print("Enter filename to decrypt: ");
                String filename = scanner.nextLine();
                
                // Second vulnerability (data exfiltration)
                String fileQuery = "SELECT content FROM encrypted_files WHERE filename='" + 
                                 filename + "'";
                ResultSet fileRs = stmt.executeQuery(fileQuery);
                
                if (fileRs.next()) {
                    System.out.println("Decrypting file...");
                    System.out.println("Content: " + fileRs.getString("content"));
                } else {
                    System.out.println("File not found!");
                }
            } else {
                System.out.println("Login failed");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}