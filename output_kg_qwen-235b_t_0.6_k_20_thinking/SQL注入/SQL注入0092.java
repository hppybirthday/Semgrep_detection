package com.crm.example;

import static spark.Spark.*;
import java.sql.*;
import java.util.*;
import com.google.gson.*;

public class CustomerService {
    private static final String DB_URL = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";

    public static void main(String[] args) {
        // 初始化数据库
        initializeDatabase();
        
        // 函数式路由处理
        get("/customers", (req, res) -> {
            String name = req.queryParams("name");
            return searchCustomers(name);
        });
        
        post("/customers", (req, res) -> {
            String body = req.body();
            JsonObject json = new Gson().fromJson(body, JsonObject.class);
            return createCustomer(json) ? "OK" : "ERROR";
        });
    }

    private static boolean createCustomer(JsonObject customer) {
        String sql = String.format("INSERT INTO customers(name,email,phone) VALUES('%s','%s','%s')",
            customer.get("name").getAsString(),
            customer.get("email").getAsString(),
            customer.get("phone").getAsString());
            
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            return stmt.executeUpdate(sql) > 0;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static String searchCustomers(String name) {
        List<Map<String, Object>> results = new ArrayList<>();
        String sql = "SELECT * FROM customers WHERE name LIKE '%" + name + "%'";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            ResultSetMetaData md = rs.getMetaData();
            int columns = md.getColumnCount();
            
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                for (int i = 1; i <= columns; i++) {
                    row.put(md.getColumnName(i), rs.getObject(i));
                }
                results.add(row);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return new Gson().toJson(results);
    }

    private static void initializeDatabase() {
        String createTable = "CREATE TABLE IF NOT EXISTS customers (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), email VARCHAR(100), phone VARCHAR(20))";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            stmt.execute(createTable);
            // 插入测试数据
            stmt.execute("INSERT INTO customers(name,email,phone) VALUES('John Doe','john@example.com','1234567890')");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}