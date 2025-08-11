import java.sql.*;
import java.util.Scanner;

public class IoTDeviceController {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/smart_home";
    private static final String USER = "admin";
    private static final String PASS = "admin123";

    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS)) {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter device ID to query status:");
            String deviceId = scanner.nextLine();
            
            // Vulnerable SQL query construction
            String sql = "SELECT status FROM devices WHERE id = '" + deviceId + "'";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {
                
                if (rs.next()) {
                    System.out.println("Device status: " + rs.getString("status"));
                } else {
                    System.out.println("Device not found");
                }
            }
            
            System.out.println("Enter new status for device (on/off): ");
            String newStatus = scanner.nextLine();
            // Vulnerable update operation
            String updateSql = "UPDATE devices SET status = '" + newStatus + 
                              "' WHERE id = '" + deviceId + "'";
            try (Statement stmt = conn.createStatement()) {
                int rowsAffected = stmt.executeUpdate(updateSql);
                System.out.println(rowsAffected + " device(s) updated");
            }
            
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }
}