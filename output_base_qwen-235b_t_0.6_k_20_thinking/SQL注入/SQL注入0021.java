package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.sql.*;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final String DB_URL = "jdbc:h2:mem:testdb";
    private final String USER = "sa";
    private final String PASS = "";

    @GetMapping("/search")
    public String searchUser(@RequestParam String username) {
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            
            // 危险的SQL拼接方式
            String sql = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = stmt.executeQuery(sql);
            
            StringBuilder result = new StringBuilder("Found users:\
");
            while (rs.next()) {
                result.append("ID: ").append(rs.getInt("id"))
                       .append(", Name: ").append(rs.getString("username"))
                       .append("\
");
            }
            return result.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 初始化数据库（测试用）
@PostConstruct
class DatabaseInitializer {
    public DatabaseInitializer() {
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50))");
            stmt.execute("INSERT INTO users VALUES (1, 'admin'), (2, 'john_doe')");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}