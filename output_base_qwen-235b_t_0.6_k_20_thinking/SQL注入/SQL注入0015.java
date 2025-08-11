package com.example.vulnerable.service;

import org.springframework.stereotype.Component;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

@Component
public class DynamicQueryEngine {
    private final String DB_URL = "jdbc:mysql://localhost:3306/cloud_auth";
    private final String USER = "root";
    private final String PASS = "secure123";

    public Map<String, Object> executeQuery(String query) throws SQLException {
        Map<String, Object> result = new HashMap<>();
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                ResultSetMetaData metaData = rs.getMetaData();
                int columnCount = metaData.getColumnCount();
                for (int i = 1; i <= columnCount; i++) {
                    result.put(metaData.getColumnName(i), rs.getObject(i));
                }
            }
        }
        return result;
    }
}

package com.example.vulnerable.controller;

import com.example.vulnerable.service.DynamicQueryEngine;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final DynamicQueryEngine queryEngine;

    public AuthController(DynamicQueryEngine engine) {
        this.queryEngine = engine;
    }

    @GetMapping("/login")
    public Map<String, Object> login(@RequestParam String username, @RequestParam String password) {
        try {
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            return queryEngine.executeQuery(query);
        } catch (SQLException e) {
            throw new RuntimeException("Database error: " + e.getMessage());
        }
    }
}

// Application.java (Spring Boot main class)
package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}