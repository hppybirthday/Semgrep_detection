package com.example.vulnerableapp;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.*;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            
            // SQL注入漏洞点：直接拼接用户输入到查询字符串中
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            
            try (ResultSet rs = stmt.executeQuery(query)) {
                if (rs.next()) {
                    response.getWriter().println("登录成功，欢迎 " + username);
                } else {
                    response.getWriter().println("登录失败：无效的用户名或密码");
                }
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
            response.getWriter().println("数据库错误：" + e.getMessage());
        }
    }
    
    @Override
    public void init() throws ServletException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new ServletException("MySQL JDBC驱动加载失败", e);
        }
    }
    
    // 函数式编程风格的辅助方法
    private void withResource(Connection conn, ThrowingConsumer<Connection> consumer) {
        try {
            consumer.accept(conn);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

@FunctionalInterface
interface ThrowingConsumer<T> {
    void accept(T t) throws SQLException;
}