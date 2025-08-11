import static spark.Spark.*;
import java.sql.*;
import java.util.*;

public class VulnerableWebApp {
    public static void main(String[] args) throws Exception {
        String url = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
        String user = "sa";
        String password = "";

        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
                stmt.execute("INSERT INTO users VALUES (1, 'admin', 'secure123'), (2, 'guest', 'guest123')");
            }
        }

        get("/login", (req, res) -> {
            return "<form method='post'>" +
                   "Username: <input type='text' name='username'><br>" +
                   "Password: <input type='password' name='password'><br>" +
                   "<input type='submit' value='Login'>" +
                   "</form>";
        });

        post("/login", (req, res) -> {
            String username = req.queryParams("username");
            String pass = req.queryParams("password");
            
            try (Connection conn = DriverManager.getConnection(url, user, password)) {
                Statement stmt = conn.createStatement();
                String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + pass + "'";
                ResultSet rs = stmt.executeQuery(query);

                if (rs.next()) {
                    return "Welcome " + rs.getString("username") + "! <a href='/login'>Logout</a>";
                } else {
                    return "Login failed. <a href='/login'>Try again</a>";
                }
            } catch (Exception e) {
                return "Database error: " + e.getMessage();
            }
        });
    }
}