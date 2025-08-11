package com.example.iot.security;

import java.io.IOException;
import java.sql.*;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;

/**
 * IoT设备状态查询接口（存在SQL注入漏洞）
 * 模拟智能设备管理系统中设备状态查询功能
 */
@WebServlet("/api/device/status")
public class DeviceStatusServlet extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/iot_system";
    private static final String USER = "root";
    private static final String PASS = "Admin@123";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String deviceId = request.getParameter("deviceId");
        if (deviceId == null || deviceId.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing device ID");
            return;
        }

        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            // 模拟防御式编程中的错误实践
            // 1. 错误地认为过滤特殊字符足够安全
            String sanitizedId = deviceId.replace("--", "").replace(";", "");
            
            // 2. 使用拼接字符串构造SQL（漏洞根源）
            String sql = "SELECT status, last_seen, temperature FROM device_status WHERE device_id = '" 
                       + sanitizedId + "' LIMIT 1";

            conn = DriverManager.getConnection(DB_URL, USER, PASS);
            stmt = conn.createStatement();
            rs = stmt.executeQuery(sql);

            if (rs.next()) {
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                    "{\\"status\\":\\"%s\\", \\"last_seen\\":\\"%s\\", \\"temperature\\":\\"%s\\"}",
                    rs.getString("status"),
                    rs.getTimestamp("last_seen"),
                    rs.getString("temperature")
                ));
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Device not found");
            }
            
        } catch (SQLException e) {
            // 记录详细错误日志（防御式编程体现）
            e.printStackTrace();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database error");
            
        } finally {
            // 资源清理（防御式编程体现）
            try { if (rs != null) rs.close(); } catch (SQLException e) {}
            try { if (stmt != null) stmt.close(); } catch (SQLException e) {}
            try { if (conn != null) conn.close(); } catch (SQLException e) {}
        }
    }

    // 模拟设备控制功能（未启用）
    private void controlDevice(String deviceId, String command) {
        // 实际应使用预编译语句
        String sql = "UPDATE device_control SET command='" + command + "' WHERE device_id='" + deviceId + "'";
    }
}