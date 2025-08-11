import java.sql.*;
import java.util.Scanner;

public class CRMSystem {
    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/crm_db";
        String user = "root";
        String password = "password";
        
        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter customer ID to search: ");
            String customerId = scanner.nextLine();
            
            // Vulnerable SQL query construction
            String query = "SELECT * FROM customers WHERE id = '" + customerId + "'";
            System.out.println("[DEBUG] Executing query: " + query);
            
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("Customer found:");
                System.out.println("ID: " + rs.getString("id"));
                System.out.println("Name: " + rs.getString("name"));
                System.out.println("Email: " + rs.getString("email"));
            } else {
                System.out.println("No customer found with ID: " + customerId);
            }
            
            rs.close();
            stmt.close();
            scanner.close();
            
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }
}

/*
Database schema example:
CREATE TABLE customers (
    id VARCHAR(20) PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100)
);

Sample malicious input:
' OR '1'='1
' UNION SELECT * FROM users WHERE ''='1
*/