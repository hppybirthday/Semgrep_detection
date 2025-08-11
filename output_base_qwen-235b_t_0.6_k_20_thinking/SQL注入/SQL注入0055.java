import java.sql.*;
import java.util.Scanner;

public class GameDatabase {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/game_db", "root", "password");
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            
            // 元编程风格的SQL构造
            String query = String.format(
                "SELECT * FROM users WHERE username='%s' AND password='%s'",
                username, password
            );
            
            System.out.println("[DEBUG] Executing query: " + query);
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("Login successful! Welcome to the game, " + rs.getString("username"));
                System.out.println("Your high score: " + rs.getInt("high_score"));
            } else {
                System.out.println("Invalid credentials. Access denied.");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

/*
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL,
    high_score INT DEFAULT 0
);

INSERT INTO users (username, password, high_score) VALUES
('admin', 'admin123', 99999),
('player1', 'pass1', 1500);
*/