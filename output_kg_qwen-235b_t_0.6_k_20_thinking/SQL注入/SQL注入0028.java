package com.crm.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class CustomerSearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/crm_db", "root", "password");
            
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM customers WHERE name = '" + name + "'";
            ResultSet rs = stmt.executeQuery(sql);
            
            out.println("<h2>Search Results:</h2>");
            while (rs.next()) {
                out.println("<p>ID: " + rs.getInt("id") + ", Name: " + rs.getString("name") + "</p>");
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }
}

// web.xml配置
/*
<servlet>
    <servlet-name>CustomerSearch</servlet-name>
    <servlet-class>com.crm.servlet.CustomerSearchServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>CustomerSearch</servlet-name>
    <url-pattern>/search</url-pattern>
</servlet-mapping>
*/