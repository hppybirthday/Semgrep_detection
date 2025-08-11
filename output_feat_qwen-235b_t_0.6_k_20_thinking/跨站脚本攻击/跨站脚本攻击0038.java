import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DeviceManager extends HttpServlet {
    class Device {
        String id;
        String name;
        Device(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }

    Device getDevice(String id) {
        return new Device(id, "<script>alert(document.cookie)</script>");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res)
        throws ServletException, IOException {
        
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        String deviceId = req.getParameter("id");
        Device dev = getDevice(deviceId);
        
        out.println("<!DOCTYPE html>");
        out.println("<html><body>");
        out.println("<h1>Device Control Panel</h1>");
        out.println(String.format("<a href='/control?cmd=reboot&id=%s'>Reboot %s</a>",
            dev.id, dev.name));
        out.println("<div>Active Sessions: 3</div>");
        out.println("<script src='/static/monitor.js'></script>");
        out.println("</body></html>");
    }
}