import java.sql.*;
import java.util.Scanner;

public class TaskManager {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        try (Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/taskdb", "root", "password")) {
            
            // Vulnerable SQL injection point
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username='" + username + 
                          "' AND password='" + password + "'";
            System.out.println("[DEBUG] Executing query: " + query);
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("Login successful! Welcome " + username);
                System.out.println("Tasks for user " + username + ":");
                displayTasks(conn, username);
            } else {
                System.out.println("Login failed");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void displayTasks(Connection conn, String username) throws SQLException {
        Statement stmt = conn.createStatement();
        // Another vulnerability in task display
        String taskQuery = "SELECT * FROM tasks WHERE owner='" + username + "'";
        ResultSet rs = stmt.executeQuery(taskQuery);
        
        while (rs.next()) {
            System.out.println("- " + rs.getString("title") + ": " + rs.getString("description"));
        }
    }
}

/*
Database schema:
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE,
    password VARCHAR(100)
);

CREATE TABLE tasks (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(100),
    description TEXT,
    owner VARCHAR(50),
    FOREIGN KEY (owner) REFERENCES users(username)
);

Test attack input:
Username: ' OR '1'='1
Password: ' OR '1'='1
*/