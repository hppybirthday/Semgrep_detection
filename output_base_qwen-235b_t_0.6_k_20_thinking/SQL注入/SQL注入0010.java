import java.sql.*;
import java.util.Scanner;

public class DataCleaner {
    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/datacleaner";
        String user = "root";
        String password = "password";
        
        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement()) {
            
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter date to clean (YYYY-MM-DD format): ");
            String userInput = scanner.nextLine();
            
            // Vulnerable SQL query construction
            String sql = "DELETE FROM raw_data WHERE created_at < '" + userInput + "'";
            System.out.println("Executing SQL: " + sql);
            
            // Execute data cleaning
            int rowsAffected = stmt.executeUpdate(sql);
            System.out.println("Data cleaning completed. Rows affected: " + rowsAffected);
            
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }
}

/*
Database schema for testing:
CREATE TABLE raw_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    content TEXT NOT NULL,
    created_at DATE NOT NULL
);
*/