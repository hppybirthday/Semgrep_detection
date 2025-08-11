import java.io.*;
import javax.servlet.*;
import javax.servlet.annotation.*;
import javax.servlet.http.*;
import java.util.*;

@WebServlet("/device")
public class DeviceController extends HttpServlet {
    private Map<String, Device> devices = new HashMap<>();

    @Override
    public void init() {
        devices.put("sensor001", new Device("sensor001", "<script>alert('XSS')</script>"));
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String id = request.getParameter("id");
        if (id == null || !devices.containsKey(id)) {
            request.setAttribute("error", "Invalid device ID: " + id);
            request.getRequestDispatcher("/error.jsp").forward(request, response);
            return;
        }

        Device device = devices.get(id);
        request.setAttribute("device", device);
        request.getRequestDispatcher("/device.jsp").forward(request, response);
    }

    static class Device {
        String id;
        String name;

        Device(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }
}

// device.jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Device Control</title></head>
<body>
    <h1>Device Configuration</h1>
    <form method="post">
        Device Name: <input type="text" value="${device.name}"><br>
        Device ID: ${device.id}<br>
        <input type="submit" value="Update">
    </form>
</body>
</html>

// error.jsp
<%@ page isErrorPage="true" contentType="text/html;charset=UTF-8" %>
<html>
<head><title>Error</title></head>
<body>
    <h1>Error: ${error}</h1>
</body>
</html>