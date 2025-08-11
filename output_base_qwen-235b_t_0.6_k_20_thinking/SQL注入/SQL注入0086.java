import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.sql.*;

public class DeviceDataServlet extends HttpServlet {
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

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        
        String action = request.getParameter("action");
        String deviceId = request.getParameter("device_id");
        
        try {
            if (action.equals("collect")) {
                String sensorData = request.getParameter("data");
                // 插入传感器数据（安全）
                PreparedStatement stmt = connection.prepareStatement(
                    "INSERT INTO sensor_data (device_id, value) VALUES (?, ?)");
                stmt.setString(1, deviceId);
                stmt.setString(2, sensorData);
                stmt.executeUpdate();
                
            } else if (action.equals("query")) {
                // 存在SQL注入漏洞的查询
                Statement stmt = connection.createStatement();
                String query = "SELECT * FROM devices WHERE id = '" + deviceId + "'";
                ResultSet rs = stmt.executeQuery(query); // 危险操作
                
                while (rs.next()) {
                    response.getWriter().println("Device: " + rs.getString("name"));
                }
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void destroy() {
        try { if (connection != null) connection.close(); } catch (SQLException e) {}
    }
}