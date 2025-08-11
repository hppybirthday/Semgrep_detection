import java.sql.*;
import java.util.Scanner;

public class ChatServer {
    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/chatdb", "user", "pass")) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter username: ");
            String user = scanner.nextLine();
            System.out.print("Enter message: ");
            String msg = scanner.nextLine();
            
            Statement stmt = conn.createStatement();
            String query = "INSERT INTO messages (username, content) VALUES ('" + user + "', '" + msg + "')";
            stmt.executeUpdate(query);
            System.out.println("Message sent!");
            
            // Display all messages
            ResultSet rs = stmt.executeQuery("SELECT * FROM messages");
            while (rs.next()) {
                System.out.println(rs.getString("username") + ": " + rs.getString("content"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}