package com.example.vulnerableapp;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.*;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    private Connection connection;

    @Override
    public void init() throws ServletException {
        try {
            // 使用H2内存数据库作为示例
            Class.forName("org.h2.Driver");
            connection = DriverManager.getConnection(
                "jdbc:h2:mem:testdb", "sa", "");
            
            // 创建用户表并插入测试数据
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
                stmt.execute("INSERT INTO users (id, username, password) VALUES (1, 'admin', 'admin123')");
                stmt.execute("INSERT INTO users (id, username, password) VALUES (2, 'guest', 'guest123')");
            }
        } catch (Exception e) {
            throw new ServletException("数据库初始化失败", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        try {
            // 存在漏洞的SQL语句拼接
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                out.println("<h2>登录成功，欢迎 " + rs.getString("username") + "!</h2>");
                // 漏洞利用示例：攻击者可通过输入以下内容查看所有用户
                // 用户名输入：' OR '1'='1
                // 密码输入：任意
                out.println("<p>你的用户ID: " + rs.getString("id") + "</p>");
            } else {
                out.println("<h2>登录失败：用户名或密码错误</h2>");
            }
            
            stmt.close();
            rs.close();
            
        } catch (SQLException e) {
            // 漏洞利用示例：攻击者可通过输入恶意输入触发SQL错误
            out.println("<h3>数据库错误: " + e.getMessage() + "</h3>");
            e.printStackTrace();
        } finally {
            out.close();
        }
    }

    @Override
    public void destroy() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}