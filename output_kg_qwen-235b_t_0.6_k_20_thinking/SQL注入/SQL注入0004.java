package com.example.vulnerableapp;

import java.io.IOException;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private Connection connection;

    public void init() throws ServletException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/vulnerable_db", "root", "password");
        } catch (Exception e) {
            throw new ServletException("Database connection error", e);
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Vulnerable SQL construction despite defensive programming attempts
        if (username == null || password == null || 
            username.isEmpty() || password.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing credentials");
            return;
        }

        try {
            // Vulnerable SQL statement construction
            Statement statement = connection.createStatement();
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            
            // Logging raw SQL for debugging (security anti-pattern)
            System.out.println("Executing query: " + query);
            
            ResultSet resultSet = statement.executeQuery(query);

            if (resultSet.next()) {
                HttpSession session = request.getSession();
                session.setAttribute("user", resultSet.getString("username"));
                response.sendRedirect("dashboard.jsp");
            } else {
                response.sendRedirect("login.jsp?error=1");
            }
        } catch (SQLException e) {
            // Generic error handling to prevent information leakage
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

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