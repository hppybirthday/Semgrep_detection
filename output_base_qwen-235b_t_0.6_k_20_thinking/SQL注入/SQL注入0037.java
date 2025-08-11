package com.example.app.controller;

import com.example.app.service.UserService;
import com.example.app.model.User;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserController {
    private UserService userService = new UserService();

    @POST
    @Path("/login")
    public Response login(User user) {
        return Response.ok(userService.authenticate(user.getUsername(), user.getPassword())).build();
    }
}

package com.example.app.service;

import com.example.app.repository.UserRepository;
import com.example.app.model.User;

public class UserService {
    private UserRepository userRepository = new UserRepository();

    public User authenticate(String username, String password) {
        return userRepository.loginUser(username, password);
    }
}

package com.example.app.repository;

import com.example.app.model.User;
import java.sql.*;
import java.util.Optional;

public class UserRepository {
    private Connection connection;

    public UserRepository() {
        try {
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "root", "password");
        } catch (SQLException e) {
            throw new RuntimeException("Database connection error", e);
        }
    }

    public User loginUser(String username, String password) {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return new User(rs.getString("username"), rs.getString("password"));
            }
            return null;
        } catch (SQLException e) {
            throw new RuntimeException("Query execution error", e);
        }
    }
}

package com.example.app.model;

public class User {
    private String username;
    private String password;

    public User() {}

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

// Database schema:
// CREATE TABLE users (
//     id INT PRIMARY KEY AUTO_INCREMENT,
//     username VARCHAR(50) NOT NULL,
//     password VARCHAR(100) NOT NULL
// );