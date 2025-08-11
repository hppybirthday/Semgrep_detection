import java.sql.*;
import java.util.Scanner;
import java.util.function.Consumer;

public class CRMSystem {
    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "")) {
            setupDatabase(conn);
            
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter customer email:");
            String email = scanner.nextLine();
            
            // Vulnerable query - string concatenation
            String query = "SELECT * FROM customers WHERE email = '" + email + "'";
            
            executeQuery(conn, query, rs -> {
                try {
                    if (!rs.isBeforeFirst()) {
                        System.out.println("No customer found");
                        return;
                    }
                    while (rs.next()) {
                        System.out.println("Found: " + rs.getString("name") + ", " + rs.getString("email"));
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            });
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void setupDatabase(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(100), email VARCHAR(100), phone VARCHAR(20))");
            stmt.execute("INSERT INTO customers VALUES (1, 'John Doe', 'john@example.com', '1234567890')");
            stmt.execute("INSERT INTO customers VALUES (2, 'Jane Smith', 'jane@example.com', '0987654321')");
        }
    }

    private static void executeQuery(Connection conn, String query, Consumer<ResultSet> consumer) throws SQLException {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            consumer.accept(rs);
        }
    }
}