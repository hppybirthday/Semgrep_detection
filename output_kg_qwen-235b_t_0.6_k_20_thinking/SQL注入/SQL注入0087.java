package com.gamestudio.desktop.domain.user;

import java.sql.*;
import java.util.Optional;

/**
 * 用户实体类（聚合根）
 */
public class User {
    private String username;
    private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getters and setters
    public String getUsername() { return username; }
    public String getPassword() { return password; }
}

/**
 * 仓储接口定义
 */
interface UserRepository {
    Optional<User> login(String username, String password);
}

/**
 * 仓储实现类（存在漏洞的关键位置）
 */
class UserRepositoryImpl implements UserRepository {
    private Connection connection;

    public UserRepositoryImpl(Connection connection) {
        this.connection = connection;
    }

    @Override
    public Optional<User> login(String username, String password) {
        try {
            // 漏洞点：直接拼接SQL语句
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                return Optional.of(new User(
                    rs.getString("username"),
                    rs.getString("password")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }
}

/**
 * 应用服务层
 */
class UserService {
    private UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean authenticate(String username, String password) {
        return userRepository.login(username, password).isPresent();
    }
}

/**
 * 客户端代码
 */
public class GameLauncher {
    public static void main(String[] args) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/game_db", "root", "password");
            
            UserRepository repo = new UserRepositoryImpl(conn);
            UserService service = new UserService(repo);
            
            // 模拟用户输入（攻击示例：' OR '1'='1）
            String userInput = "admin' OR '1'='1";
            boolean loginSuccess = service.authenticate(userInput, "any_password");
            
            System.out.println("登录结果：" + (loginSuccess ? "成功" : "失败"));
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}