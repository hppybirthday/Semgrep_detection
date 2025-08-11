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
    private static final String DB_PASSWORD = "secure123";

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Defensive programming attempt (incomplete)
        if (username == null || password == null || 
            username.isEmpty() || password.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing credentials");
            return;
        }

        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            // Vulnerable database connection
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            stmt = conn.createStatement();
            
            // SQL Injection vulnerability here (string concatenation)
            String sql = "SELECT * FROM users WHERE username = '" + username + 
                         "' AND password = '" + password + "'";
            
            rs = stmt.executeQuery(sql);
            
            if (rs.next()) {
                // Successful login
                HttpSession session = request.getSession();
                session.setAttribute("user", rs.getString("username"));
                response.sendRedirect("dashboard.jsp");
            } else {
                // Login failed
                response.sendRedirect("login.jsp?error=1");
            }
            
        } catch (SQLException e) {
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } finally {
            // Resource cleanup (incomplete)
            try {
                if (rs != null) rs.close();
                if (stmt != null) stmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}