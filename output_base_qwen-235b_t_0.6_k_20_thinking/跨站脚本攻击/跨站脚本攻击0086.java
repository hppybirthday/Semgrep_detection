import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.*;

@WebServlet("/device/control")
public class DeviceController extends HttpServlet {
    private Map<String, String> devices = new HashMap<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String action = request.getParameter("action");
        String deviceId = request.getParameter("deviceId");
        String deviceName = request.getParameter("deviceName");
        
        if ("register".equals(action)) {
            devices.put(deviceId, deviceName);
            request.setAttribute("status", "Device registered");
        } else if ("update".equals(action)) {
            if (devices.containsKey(deviceId)) {
                devices.put(deviceId, deviceName);
                request.setAttribute("status", "Device updated");
            }
        }
        
        request.setAttribute("devices", devices);
        request.getRequestDispatcher("/device_status.jsp").forward(response, request);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        doPost(request, response);
    }
}

// device_status.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>IoT Device Status</title></head>
<body>
    <h1>Device Management</h1>
    <p>Status: ${status}</p>
    
    <table border="1">
        <tr><th>Device ID</th><th>Name</th></tr>
        <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
        <c:forEach items="${devices}" var="entry">
            <tr>
                <td>${entry.key}</td>
                <td>${entry.value}</td>
            </tr>
        </c:forEach>
    </table>
    
    <form method="post">
        Action: <select name="action">
            <option value="register">Register</option>
            <option value="update">Update</option>
        </select><br>
        Device ID: <input type="text" name="deviceId"><br>
        Device Name: <input type="text" name="deviceName"><br>
        <input type="submit" value="Submit">
    </form>
</body>
</html>