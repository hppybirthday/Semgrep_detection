package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Method;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/users")
public class SqlInjectionDemo {
    static String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    static String USER = "root";
    static String PASS = "password";

    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemo.class, args);
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody User user) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
        
        // 使用反射动态构建查询（元编程特征）
        StringBuilder query = new StringBuilder("SELECT * FROM users WHERE ");
        Method[] methods = User.class.getDeclaredMethods();
        Map<String, String> params = new HashMap<>();
        
        for (Method method : methods) {
            if (method.getName().startsWith("get")) {
                String fieldName = method.getName().substring(3).toLowerCase();
                Object value = method.invoke(user);
                if (value != null) {
                    // 漏洞点：直接拼接用户输入
                    query.append(fieldName).append("='").append(value).append("' AND ");
                    params.put(fieldName, value.toString());
                }
            }
        }
        
        if (params.isEmpty()) {
            throw new IllegalArgumentException("No valid parameters");
        }
        
        // 删除末尾多余的 AND
        query.setLength(query.length() - 5);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query.toString());
        
        Map<String, Object> result = new HashMap<>();
        if (rs.next()) {
            result.put("user", rs.getString("username"));
            result.put("role", rs.getString("role"));
        } else {
            result.put("error", "Invalid credentials");
        }
        
        rs.close();
        stmt.close();
        conn.close();
        return result;
    }

    static class User {
        private String username;
        private String password;
        
        // Getters and setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}