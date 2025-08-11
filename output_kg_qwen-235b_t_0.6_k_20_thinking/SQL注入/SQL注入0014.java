package com.example.app;

import java.sql.*;
import java.util.logging.Logger;

public class UserService {
    private static final Logger logger = Logger.getLogger(UserService.class.getName());
    private Connection connection;

    public UserService() {
        try {
            // 使用H2内存数据库模拟
            connection = DriverManager.getConnection("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");
            initDatabase();
        } catch (SQLException e) {
            logger.severe("Database connection error: " + e.getMessage());
        }
    }

    private void initDatabase() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
            // 插入测试数据
            stmt.execute("INSERT INTO users (id, username, password) VALUES (1, 'admin', 'admin123')");
        }
    }

    // 易受攻击的查询方法
    public boolean authenticate(String username, String password) {
        if (username == null || password == null || username.length() > 50 || password.length() > 50) {
            logger.warning("Invalid input length");
            return false;
        }

        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                logger.info("Authentication successful for: " + username);
                return true;
            }
            
        } catch (SQLException e) {
            logger.warning("Authentication error: " + e.getMessage());
        }
        
        return false;
    }

    // 模拟API端点
    public static void main(String[] args) {
        UserService service = new UserService();
        
        // 模拟用户输入
        String userInput = "' OR '1'='1"; // 恶意输入示例
        
        System.out.println("Attempting authentication with payload: " + userInput);
        boolean result = service.authenticate("admin", userInput);
        
        System.out.println("Authentication result: " + (result ? "SUCCESS" : "FAILED"));
    }
}