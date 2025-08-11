package com.example.vulnerableapp;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 模拟数据库连接
public class DBUtil {
    public static Connection getConnection() {
        try {
            Class.forName("org.h2.Driver");
            return DriverManager.getConnection(
                "jdbc:h2:mem:testdb", "sa", "");
        } catch (Exception e) {
            throw new RuntimeException("Database connection error", e);
        }
    }
}

// 用户实体类
class User {
    private int id;
    private String username;
    private String email;

    // 构造方法/getter/setter省略
    public User(int id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }
}

// 数据访问层
class UserDAO {
    // 漏洞点：直接拼接SQL语句
    public List<User> searchUsers(String username, String email) {
        List<User> users = new ArrayList<>();
        String query = "SELECT id, username, email FROM users WHERE ";
        
        if (username != null && !username.isEmpty()) {
            query += "username = '" + username + "'";
        }
        
        if (email != null && !email.isEmpty()) {
            if (username != null && !username.isEmpty()) {
                query += " AND ";
            }
            query += "email = '" + email + "'";
        }

        try (Connection conn = DBUtil.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {

            while (rs.next()) {
                users.add(new User(
                    rs.getInt("id"),
                    rs.getString("username"),
                    rs.getString("email")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return users;
    }
}

// 业务服务层
class UserService {
    private UserDAO userDAO = new UserDAO();

    public List<User> findUsers(String username, String email) {
        return userDAO.searchUsers(username, email);
    }
}

// REST控制器
public class UserController {
    private UserService userService = new UserService();

    // 模拟处理GET请求
    public void handleSearch(String username, String email) {
        System.out.println("Received request with username: " + username + ", email: " + email);
        List<User> results = userService.findUsers(username, email);
        
        System.out.println("Search results:");
        for (User user : results) {
            System.out.println("ID: " + user.id + ", Username: " + user.username + ", Email: " + user.email);
        }
    }

    public static void main(String[] args) {
        // 初始化数据库
        try (Connection conn = DBUtil.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50), email VARCHAR(100))");
            stmt.execute("INSERT INTO users VALUES (1, 'admin', 'admin@example.com')");
            stmt.execute("INSERT INTO users VALUES (2, 'testuser', 'test@example.com')");
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // 模拟攻击示例
        UserController controller = new UserController();
        System.out.println("--- 正常查询 ---");
        controller.handleSearch("admin", null);
        
        System.out.println("\
--- SQL注入攻击示例 ---");
        // 注入载荷：' OR '1'='1
        controller.handleSearch("' OR '1'='1", null);
    }
}