package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class SqlInjectionDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemoApplication.class, args);
    }

    @Controller
    public static class UserController {

        private Connection getConnection() throws SQLException {
            return DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/testdb", "root", "password");
        }

        @PostMapping("/login")
        @ResponseBody
        public String login(@RequestParam String username, @RequestParam String password) {
            try {
                Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                
                // 漏洞点：直接拼接SQL语句
                String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
                ResultSet rs = stmt.executeQuery(query);

                if (rs.next()) {
                    return "Login successful for user: " + rs.getString("username");
                }
                return "Invalid credentials";
            } catch (SQLException e) {
                return "Error: " + e.getMessage();
            }
        }

        @PostMapping("/users")
        @ResponseBody
        public List<String> searchUsers(@RequestParam String searchTerm) {
            List<String> results = new ArrayList<>();
            try {
                Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                
                // 漏洞点：搜索功能存在SQL注入
                String query = "SELECT username FROM users WHERE username LIKE '%" + searchTerm + "%'";
                ResultSet rs = stmt.executeQuery(query);

                while (rs.next()) {
                    results.add(rs.getString("username"));
                }
            } catch (SQLException e) {
                results.add("Error: " + e.getMessage());
            }
            return results;
        }

        @PostMapping("/delete")
        @ResponseBody
        public String deleteUser(@RequestParam String userId) {
            try {
                Connection conn = getConnection();
                Statement stmt = conn.createStatement();
                
                // 漏洞点：用户ID未使用预编译语句
                String query = "DELETE FROM users WHERE id = " + userId;
                stmt.executeUpdate(query);
                return "User deleted successfully";
            } catch (SQLException e) {
                return "Error: " + e.getMessage();
            }
        }
    }
}