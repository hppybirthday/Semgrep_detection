import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DeviceServlet extends HttpServlet {
    private static String lastStatus = "";
    
    protected void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException {
        String device = req.getParameter("device");
        String status = req.getParameter("status");
        lastStatus = "Device: " + device + " Status: " + status;
        res.sendRedirect("status.jsp");
    }
}

// status.jsp
<%@ page language="java" contentType="text/html; charset=UTF-8"%>
<html><body>
<h1>Device Status</h1>
<div>${lastStatus}</div>
<form action="log.jsp">
    <input type="text" name="device">
    <input type="text" name="status">
    <input type="submit">
</form>
</body></html>

// web.xml
<servlet>
    <servlet-name>DeviceServlet</servlet-name>
    <servlet-class>DeviceServlet</servlet-class>
</servlet>
<servlet-mapping>
    <servlet-name>DeviceServlet</servlet-name>
    <url-pattern>/update</url-pattern>
</servlet-mapping>