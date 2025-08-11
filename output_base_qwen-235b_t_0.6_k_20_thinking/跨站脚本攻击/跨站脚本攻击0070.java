import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DeviceController extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String deviceName = request.getParameter("deviceName");
        String sensorData = getSensorData(deviceName);
        
        request.setAttribute("deviceName", deviceName);
        request.setAttribute("sensorData", sensorData);
        
        request.getRequestDispatcher("/deviceStatus.jsp").forward(request, response);
    }

    private String getSensorData(String deviceName) {
        // 模拟从设备读取数据
        if(deviceName.contains("<script>")) {
            return "Error: Invalid device name";
        }
        return String.format("{temperature: 25.5, humidity: 60, timestamp: %d}", System.currentTimeMillis());
    }
}

// deviceStatus.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Device Status</title></head>
<body>
    <h1>Device: <%= request.getAttribute("deviceName") %></h1>
    <div id="data">
        Raw Sensor Data: <%= request.getAttribute("sensorData") %>
    </div>
    <form method="POST">
        <input type="text" name="deviceName" value="<%= request.getAttribute("deviceName") %>">
        <input type="submit" value="Update">
    </form>
    <script>
        // 模拟前端解析数据
        var dataContainer = document.getElementById('data');
        var rawData = dataContainer.innerHTML;
        try {
            var parsed = JSON.parse(rawData.split(": ")[1]);
            console.log("Parsed sensor data:", parsed);
        } catch (e) {
            console.error("Invalid data format");
        }
    </script>
</body>
</html>