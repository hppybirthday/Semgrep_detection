package com.example.datacleaner;

import java.sql.*;
import java.util.Scanner;

public class DataCleaner {
    private static Connection connection;

    public static void main(String[] args) {
        try {
            // 模拟数据库连接初始化
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/datacleaner_db", "root", "password");
            
            Scanner scanner = new Scanner(System.in);
            System.out.println("请输入需要清理的字段名：");
            String fieldName = scanner.nextLine();
            System.out.println("请输入字段值：");
            String value = scanner.nextLine();
            
            // 模拟数据清洗操作：删除匹配记录
            String query = "DELETE FROM user_data WHERE " + fieldName + " = '" + value + "'";
            System.out.println("执行SQL: " + query);
            
            Statement statement = connection.createStatement();
            int rowsAffected = statement.executeUpdate(query);
            System.out.println("受影响记录数: " + rowsAffected);
            
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (connection != null && !connection.isClosed()) {
                    connection.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    // 模拟数据库初始化方法（实际场景中可能由其他组件调用）
    public static void initializeDatabase() throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS user_data (id INT PRIMARY KEY, username VARCHAR(50), email VARCHAR(100))");
        // 插入测试数据
        stmt.execute("INSERT INTO user_data VALUES (1, 'test_user', 'test@example.com')");
    }
}