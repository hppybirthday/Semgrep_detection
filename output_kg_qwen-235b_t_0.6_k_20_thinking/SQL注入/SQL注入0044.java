package com.crm.example;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 客户关系管理系统中的订单查询模块
 * 存在SQL注入漏洞的示例代码
 */
public class OrderService {
    private Connection connection;

    public OrderService(Connection connection) {
        this.connection = connection;
    }

    /**
     * 根据客户名称查询订单（存在SQL注入漏洞）
     * @param customerName 客户名称
     * @return 订单列表
     */
    public List<String> getOrdersByCustomerName(String customerName) {
        List<String> orders = new ArrayList<>();
        
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT order_id, amount FROM orders WHERE customer_name = '" 
                     + sanitizeInput(customerName) + "' ORDER BY order_date DESC";
        
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                orders.add("订单ID: " + rs.getString("order_id") 
                          + ", 金额: " + rs.getDouble("amount"));
            }
            
        } catch (SQLException e) {
            System.err.println("查询订单时发生错误: " + e.getMessage());
        }
        
        return orders;
    }
    
    /**
     * 输入过滤函数（防御式编程的错误示范）
     * 试图通过替换单引号来防止SQL注入
     * @param input 用户输入
     * @return 处理后的输入
     */
    private String sanitizeInput(String input) {
        // 试图过滤特殊字符（存在漏洞：无法处理编码绕过）
        if (input == null) return "";
        
        // 错误的过滤方式：仅替换英文单引号
        return input.replace("'", "");
    }
    
    /**
     * 模拟数据库初始化
     */
    public static void initializeDatabase(Connection conn) {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS orders (" +
                          "order_id VARCHAR(20) PRIMARY KEY, " +
                          "customer_name VARCHAR(100), " +
                          "amount DECIMAL(10,2), " +
                          "order_date DATE)");
            
            // 插入测试数据
            stmt.execute("INSERT INTO orders (order_id, customer_name, amount, order_date) " +
                          "VALUES ('ORD001', '张三', 1500.00, '2023-07-15')");
            stmt.execute("INSERT INTO orders (order_id, customer_name, amount, order_date) " +
                          "VALUES ('ORD002', '李四', 800.50, '2023-07-16')");
            
        } catch (SQLException e) {
            System.err.println("数据库初始化失败: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/crm_db", "user", "password")) {
            OrderService orderService = new OrderService(conn);
            initializeDatabase(conn);
            
            // 模拟用户输入
            String userInput = "张三"; // 正常输入
            // String userInput = "张三' OR '1'='1"; // 恶意输入
            
            System.out.println("查询客户 '" + userInput + "' 的订单:");
            List<String> result = orderService.getOrdersByCustomerName(userInput);
            
            result.forEach(System.out::println);
            
        } catch (SQLException e) {
            System.err.println("数据库连接失败: " + e.getMessage());
        }
    }
}