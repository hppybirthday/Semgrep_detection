import java.sql.*;
import java.util.Scanner;

public class BankLogin {
    public static void main(String[] args) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/bankdb", "root", "password");
            System.out.println("Enter username:");
            Scanner scanner = new Scanner(System.in);
            String username = scanner.nextLine();
            System.out.println("Enter password:");
            String password = scanner.nextLine();
            
            // Vulnerable SQL query construction
            String query = "SELECT * FROM users WHERE username = '" 
                + username + "' AND password = '" + password + "'";
            
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("Login successful!");
                System.out.println("Account balance: $" + rs.getDouble("balance"));
            } else {
                System.out.println("Invalid credentials");
            }
            
            rs.close();
            stmt.close();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}