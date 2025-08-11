package com.example.vulnerableapp;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.sql.*;
import java.util.function.*;

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
            
            // Vulnerable SQL query construction
            String query = "SELECT * FROM users WHERE username = '" + username + 
                          "' AND password = '" + password + "'";
            
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                response.getWriter().println("<h1>Login Successful!</h1>");
                response.getWriter().println("Welcome " + rs.getString("full_name"));
            } else {
                response.getWriter().println("<h1>Login Failed</h1>");
                response.getWriter().println("Invalid username or password");
            }
            
        } catch (SQLException e) {
            throw new ServletException("Database error", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<form method='post'>");
        out.println("Username: <input type='text' name='username'><br>");
        out.println("Password: <input type='password' name='password'><br>");
        out.println("<input type='submit' value='Login'>");
        out.println("</form></body></html>");
    }

    // Database initialization function (simplified)
    public static void initializeDatabase() {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            
            stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "username VARCHAR(50) UNIQUE, " +
                "password VARCHAR(50), " +
                "full_name VARCHAR(100))");
            
            // Sample data initialization
            stmt.execute("INSERT IGNORE INTO users (username, password, full_name) " +
                "VALUES ('admin', 'admin123', 'System Administrator')");
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Application startup hook
    static {
        new Thread(() -> {
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
                initializeDatabase();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize database", e);
            }
        }).start();
    }
}