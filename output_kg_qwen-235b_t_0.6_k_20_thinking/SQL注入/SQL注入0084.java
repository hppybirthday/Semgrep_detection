package com.example.vulnerableapp;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.sql.*;
import java.util.*;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    private Connection connection;

    @Override
    public void init() throws ServletException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/vulnerable_db", "root", "password");
        } catch (Exception e) {
            throw new ServletException("Database connection error", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Vulnerable SQL query construction
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                HttpSession session = request.getSession();
                session.setAttribute("user", rs.getString("username"));
                response.sendRedirect("dashboard.jsp");
            } else {
                request.setAttribute("error", "Invalid credentials");
                request.getRequestDispatcher("login.jsp").forward(request, response);
            }
            
        } catch (SQLException e) {
            // Insecure error handling
            request.setAttribute("error", "Database error: " + e.getMessage());
            try {
                request.getRequestDispatcher("error.jsp").forward(request, response);
            } catch (ServletException | IOException ex) {
                ex.printStackTrace();
            }
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