package com.gamestudio.desktop;

import java.sql.*;
import java.util.Scanner;

public class GameLogin {
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
                "jdbc:mysql://localhost:3306/game_db", "root", "password");
             Statement stmt = conn.createStatement()) {
            
            // Vulnerable SQL query - string concatenation with user input
            String query = "SELECT * FROM players WHERE username = '" 
                + username + "' AND password = '" + password + "'";
            System.out.println("Executing query: " + query);
            
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("Login successful! Welcome " + rs.getString("username"));
                System.out.println("Character stats: " + rs.getString("stats"));
            } else {
                System.out.println("Invalid credentials");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

// Database schema example:
// CREATE TABLE players (
//     id INT PRIMARY KEY AUTO_INCREMENT,
//     username VARCHAR(50) UNIQUE NOT NULL,
//     password VARCHAR(100) NOT NULL,
//     stats TEXT
// );

// Sample vulnerable input:
// Username: admin'--
// Password: anything
// This would bypass password check and log in as admin