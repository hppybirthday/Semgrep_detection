package com.example.demo.service;

import com.example.demo.model.User;
import org.springframework.stereotype.Component;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@Component
public class UserService {
    private final Connection connection;

    public UserService() throws SQLException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            this.connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "user", "password");
        } catch (ClassNotFoundException | SQLException e) {
            throw new RuntimeException("Database connection error", e);
        }
    }

    public List<User> findUsers(String username, String password) throws SQLException {
        List<User> users = new ArrayList<>();
        Statement stmt = connection.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(query);
        while (rs.next()) {
            users.add(new User(rs.getInt("id"), rs.getString("username"), rs.getString("password")));
        }
        return users;
    }

    public void createUser(String username, String password) throws SQLException {
        Statement stmt = connection.createStatement();
        String query = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "')";
        stmt.executeUpdate(query);
    }
}

package com.example.demo.controller;

import com.example.demo.model.User;
import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public List<User> getAllUsers(@RequestParam String username, @RequestParam String password) throws SQLException {
        return userService.findUsers(username, password);
    }

    @PostMapping
    public void addUser(@RequestParam String username, @RequestParam String password) throws SQLException {
        userService.createUser(username, password);
    }
}

package com.example.demo.model;

public class User {
    private int id;
    private String username;
    private String password;

    public User(int id, String username, String password) {
        this.id = id;
        this.username = username;
        this.password = password;
    }

    // Getters and setters
}

// application.properties配置示例：
spring.datasource.url=jdbc:mysql://localhost:3306/mydb
spring.datasource.username=user
spring.datasource.password=password
spring.jpa.hibernate.ddl-auto=update