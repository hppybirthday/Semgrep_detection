package com.crm.demo.controller;

import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/customers")
public class CustomerController {
    private Connection connection;

    public CustomerController() {
        try {
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/crm_db", "root", "password");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/search")
    public List<Customer> searchCustomers(@RequestParam String name) {
        List<Customer> customers = new ArrayList<>();
        try {
            Statement stmt = connection.createStatement();
            // 漏洞点：直接拼接SQL语句
            ResultSet rs = stmt.executeQuery(
                "SELECT * FROM customers WHERE name LIKE '" + name + "%'"
            );
            while (rs.next()) {
                customers.add(new Customer(
                    rs.getInt("id"),
                    rs.getString("name"),
                    rs.getString("email")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return customers;
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, 
                      @RequestParam String password) {
        try {
            Statement stmt = connection.createStatement();
            // 漏洞点：用户输入直接拼接到SQL
            ResultSet rs = stmt.executeQuery(
                "SELECT * FROM users WHERE username='" + username + 
                "' AND password='" + password + "'"
            );
            if (rs.next()) {
                return "登录成功: " + rs.getString("role");
            }
            return "登录失败";
        } catch (SQLException e) {
            e.printStackTrace();
            return "系统错误";
        }
    }

    @GetMapping("/delete")
    public String deleteCustomer(@RequestParam String id) {
        try {
            Statement stmt = connection.createStatement();
            // 漏洞点：id参数未进行类型检查
            stmt.executeUpdate(
                "DELETE FROM customers WHERE id=" + id
            );
            return "删除成功";
        } catch (SQLException e) {
            e.printStackTrace();
            return "删除失败";
        }
    }
}

class Customer {
    private int id;
    private String name;
    private String email;

    public Customer(int id, String name, String email) {
        this.id = id;
        this.name = name;
        this.email = email;
    }

    // Getters and setters
    public int getId() { return id; }
    public String getName() { return name; }
    public String getEmail() { return email; }
}