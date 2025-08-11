import java.sql.*;
import java.util.Scanner;

public class DataProcessor {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter department filter: ");
        String department = scanner.nextLine();
        
        String query = "SELECT * FROM employee_data WHERE department = '" 
                     + department + "' ORDER BY salary DESC";

        try (Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/company_db", "user", "password");
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {

            int recordCount = 0;
            while (rs.next()) {
                // Simulate big data processing
                processRecord(rs.getString("name"), rs.getDouble("salary"));
                recordCount++;
                
                // Memory intensive operation
                if (recordCount % 1000 == 0) {
                    System.out.println("Processed " + recordCount + " records...");
                }
            }
            
            System.out.println("Total records processed: " + recordCount);
            
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }

    private static void processRecord(String name, double salary) {
        // Simulate complex data processing
        String mask = "\\u2588\\u2588\\u2588\\u2588\\u2588";
        System.out.printf("Processing: %s %s %.2f%n", mask, name, salary * 1.1);
    }
}