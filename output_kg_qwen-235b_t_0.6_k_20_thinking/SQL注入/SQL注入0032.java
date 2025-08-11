import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;

public class FileEncryptionTool {
    static {
        try {
            Class.forName("org.h2.Driver");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Connection createConnection() throws SQLException {
        return DriverManager.getConnection(
            "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");
    }

    public static void initializeDatabase() {
        try (Connection conn = createConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE encrypted_files (id INT PRIMARY KEY, filename VARCHAR(255), encrypted_data BLOB)"));
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void addEncryptedFile(String filename, byte[] encryptedData) {
        try (Connection conn = createConnection();
             PreparedStatement pstmt = conn.prepareStatement(
                 "INSERT INTO encrypted_files VALUES (?, ?, ?)")) {
            pstmt.setInt(1, new Random().nextInt(1000));
            pstmt.setString(2, filename);
            pstmt.setBytes(3, encryptedData);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Vulnerable function: Uses string concatenation for SQL query
    public static List<String> searchEncryptedFiles(String userInput) {
        String query = "SELECT filename FROM encrypted_files WHERE filename LIKE '" 
                     + userInput + "'";  // SQL Injection point
        
        try (Connection conn = createConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            List<String> results = new ArrayList<>();
            while (rs.next()) {
                results.add(rs.getString("filename"));
            }
            return results;
            
        } catch (SQLException e) {
            System.err.println("Query execution error: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    public static void main(String[] args) {
        initializeDatabase();
        
        // Add test data
        addEncryptedFile("secret_document.enc", "AES-256_ENCRYPTED_DATA_1".getBytes());
        addEncryptedFile("financial_report.enc", "AES-256_ENCRYPTED_DATA_2".getBytes());
        
        // Simulate user input with SQL injection
        String maliciousInput = "' OR '1'='1";  // Classic SQL injection payload
        System.out.println("Searching with input: " + maliciousInput);
        
        List<String> results = searchEncryptedFiles(maliciousInput);
        System.out.println("Matching files:");
        results.forEach(System.out::println);
        
        // Demonstrate data destruction possibility
        String dropTableInput = "'; DROP TABLE encrypted_files;--";
        System.out.println("\
Attempting to destroy database structure...");
        searchEncryptedFiles(dropTableInput);
    }
}