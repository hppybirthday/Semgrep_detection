package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.*;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class VulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApp.class, args);
    }
}

@RestController
@RequestMapping("/api/users")
class UserController {
    private final UserRepository userRepository = new UserRepository();

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest request) {
        User user = userRepository.findByUsernameAndPassword(request.username, request.password);
        Map<String, String> response = new HashMap<>();

        if (user != null) {
            response.put("status", "success");
            response.put("message", "Login successful for " + user.getUsername());
        } else {
            response.put("status", "error");
            response.put("message", "Invalid credentials");
        }
        return ResponseEntity.ok(response);
    }
}

class LoginRequest {
    String username;
    String password;
    // Getters and setters omitted for brevity
}

class UserRepository {
    private Connection connection;

    public UserRepository() {
        try {
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "root", "password");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public User findByUsernameAndPassword(String username, String password) {
        try {
            Statement stmt = connection.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + 
                          "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                return new User(rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
}

class User {
    private String username;

    public User(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}