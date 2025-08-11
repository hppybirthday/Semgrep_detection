package com.example.iot;

import java.io.IOException;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DeviceController extends HttpServlet {
    private Connection connection;

    public void init() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/iot_db", "root", "password");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
        
        String deviceId = request.getParameter("id");
        if (deviceId == null || deviceId.isEmpty()) {
            response.getWriter().write("Missing device ID");
            return;
        }

        try {
            Statement stmt = connection.createStatement();
            String query = "SELECT * FROM devices WHERE id = '" + deviceId + "'";
            ResultSet rs = stmt.executeQuery(query);

            StringBuilder result = new StringBuilder("Device Data:\
");
            while (rs.next()) {
                result.append("ID: ").append(rs.getString("id"))
                      .append(" | Temp: ").append(rs.getDouble("temperature"))
                      .append(" | Status: ").append(rs.getString("status"))
                      .append("\
");
            }
            response.getWriter().write(result.toString());

        } catch (SQLException e) {
            response.getWriter().write("Database error: " + e.getMessage());
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

/*
CREATE TABLE devices (
    id VARCHAR(50) PRIMARY KEY,
    temperature DECIMAL(5,2),
    status VARCHAR(20),
    last_updated TIMESTAMP
);

Sample vulnerable URL:
http://localhost:8080/device?id=1' UNION SELECT * FROM devices WHERE '1'='1
*/