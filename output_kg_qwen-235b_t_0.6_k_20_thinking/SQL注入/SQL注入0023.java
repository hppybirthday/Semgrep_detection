package com.gamestudio.desktop;

import java.sql.*;
import java.util.Scanner;

// 玩家实体类
class Player {
    private int id;
    private String username;
    private String password;

    public Player(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

// 数据访问层类
class PlayerDAO {
    private Connection connection;

    public PlayerDAO() throws SQLException {
        connection = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/game_db", "root", "password");
    }

    // 存在SQL注入漏洞的登录验证方法
    public boolean authenticatePlayer(String username, String password) throws SQLException {
        Statement stmt = connection.createStatement();
        // 直接拼接用户输入到SQL语句中
        String query = "SELECT * FROM players WHERE username = '" + username + "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }

    // 注册新玩家
    public void registerPlayer(Player player) throws SQLException {
        PreparedStatement pstmt = connection.prepareStatement(
            "INSERT INTO players (username, password) VALUES (?, ?)");
        pstmt.setString(1, player.getUsername());
        pstmt.setString(2, player.getPassword());
        pstmt.executeUpdate();
    }
}

// 主程序类
public class GameLoginSystem {
    public static void main(String[] args) {
        try {
            // 初始化数据库连接
            Class.forName("com.mysql.cj.jdbc.Driver");
            PlayerDAO playerDAO = new PlayerDAO();

            Scanner scanner = new Scanner(System.in);
            System.out.println("=== 游戏登录系统 ===");
            System.out.print("用户名: ");
            String username = scanner.nextLine();
            System.out.print("密码: ");
            String password = scanner.nextLine();

            // 使用存在漏洞的认证方法
            if (playerDAO.authenticatePlayer(username, password)) {
                System.out.println("登录成功! 欢迎回来, " + username);
            } else {
                System.out.println("登录失败: 无效的用户名或密码");
            }

        } catch (Exception e) {
            System.err.println("系统错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}