import java.sql.*;
public class DataCleaner {
    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/dataclean";
        String user = "root";
        String password = "pass123";
        Connection conn = null;
        Statement stmt = null;
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection(url, user, password);
            stmt = conn.createStatement();
            String id = "1";
            if (args.length > 0) id = args[0];
            String query = "DELETE FROM temp_data WHERE id = " + id;
            System.out.println("Executing: " + query);
            stmt.executeUpdate(query);
            System.out.println("Data cleaned successfully");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException se) {
                se.printStackTrace();
            }
        }
    }
}