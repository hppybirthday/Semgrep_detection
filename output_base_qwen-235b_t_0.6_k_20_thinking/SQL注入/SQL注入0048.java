import java.sql.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Username: ");
        String user = scanner.nextLine();
        System.out.print("Password: ");
        String pass = scanner.nextLine();
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/encrypt_db", "root", "pass123");
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username='" + user + "' AND password='" + pass + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("Login successful!");
                System.out.print("Enter file path to decrypt: ");
                String path = scanner.nextLine();
                String decryptQuery = "SELECT decrypt((SELECT content FROM files WHERE path='" + path + "'), (SELECT key FROM keys WHERE owner='" + user + "'))";
                ResultSet decryptRs = stmt.executeQuery(decryptQuery);
                if (decryptRs.next()) {
                    System.out.println("Decrypted content: " + decryptRs.getString(1));
                }
            } else {
                System.out.println("Authentication failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}