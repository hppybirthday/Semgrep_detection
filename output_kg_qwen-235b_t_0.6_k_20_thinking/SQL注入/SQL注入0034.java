package com.example.chatapp;

import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/search")
public class ChatSearchServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/chatdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "securePass123!";

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String keyword = request.getParameter("keyword");
        if (keyword == null || keyword.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing search keyword");
            return;
        }

        List<String> results = new ArrayList<>();
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            // Vulnerable SQL construction
            conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            String query = "SELECT message FROM chat_logs WHERE message LIKE '%" + keyword + "%'";
            
            // Attempted defense (incomplete)
            if (containsDangerousChars(keyword)) {
                throw new IllegalArgumentException("Invalid characters detected");
            }
            
            stmt = conn.createStatement();
            rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                results.add(rs.getString("message"));
            }
            
        } catch (SQLException | IllegalArgumentException e) {
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Search failed");
            return;
        } finally {
            closeResources(conn, stmt, rs);
        }
        
        response.setContentType("application/json");
        response.getWriter().write(results.toString());
    }

    private boolean containsDangerousChars(String input) {
        // Incomplete validation (misses many SQL meta-characters)
        return input.contains("'") || input.contains(";");
    }

    private void closeResources(Connection conn, Statement stmt, ResultSet rs) {
        try {
            if (rs != null) rs.close();
            if (stmt != null) stmt.close();
            if (conn != null) conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}