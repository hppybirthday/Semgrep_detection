package com.example.vulnerableapp;

import java.sql.*;
import java.util.Scanner;

public class LoginActivity {
    // 模拟数据库连接
    private static Connection connection;

    static {
        try {
            // 使用内存数据库进行演示
            connection = DriverManager.getConnection("jdbc:sqlite::memory:");
            Statement stmt = connection.createStatement();
            // 创建用户表
            stmt.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
            // 插入测试数据
            stmt.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 模拟用户登录方法（存在SQL注入漏洞）
    public boolean login(String username, String password) {
        try {
            // 危险的SQL拼接方式
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            // 模拟验证逻辑
            if (rs.next()) {
                System.out.println("登录成功！欢迎 " + rs.getString("username"));
                return true;
            } else {
                System.out.println("登录失败：用户名或密码错误");
                return false;
            }
        } catch (SQLException e) {
            System.out.println("数据库错误: " + e.getMessage());
            return false;
        }
    }

    // 模拟注册方法（同样存在漏洞）
    public void register(String username, String password) {
        try {
            // 危险的SQL拼接方式
            String query = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "')";
            Statement stmt = connection.createStatement();
            stmt.executeUpdate(query);
            System.out.println("注册成功！");
        } catch (SQLException e) {
            System.out.println("注册失败: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        LoginActivity auth = new LoginActivity();
        Scanner scanner = new Scanner(System.in);

        System.out.println("=== 漏洞演示程序 ===");
        System.out.println("1. 注册新用户");
        System.out.println("2. 用户登录");
        System.out.print("请选择操作 (1/2): ");
        
        int choice = scanner.nextInt();
        scanner.nextLine();  // 清除缓冲区

        if (choice == 1) {
            System.out.print("请输入用户名: ");
            String username = scanner.nextLine();
            System.out.print("请输入密码: ");
            String password = scanner.nextLine();
            auth.register(username, password);
        } else if (choice == 2) {
            System.out.print("请输入用户名: ");
            String username = scanner.nextLine();
            System.out.print("请输入密码: ");
            String password = scanner.nextLine();
            auth.login(username, password);
        } else {
            System.out.println("无效的选择");
        }
        
        scanner.close();
    }
}