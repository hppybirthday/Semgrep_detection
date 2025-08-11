package com.example.iot.xss;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/device/control")
public class DeviceControlServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private List<SensorData> sensorList = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String action = request.getParameter("action");
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();

        if ("addSensor".equals(action)) {
            String sensorName = request.getParameter("sensorName");
            String sensorValue = request.getParameter("sensorValue");
            
            // 模拟存储传感器数据（未转义直接存储）
            sensorList.add(new SensorData(sensorName, sensorValue));
            
            // 生成设备控制页面（存在XSS漏洞的输出）
            generateControlPage(out, "Sensor added successfully!");
        } 
        else if ("showData".equals(action)) {
            generateDataPage(out);
        }
        else {
            generateControlPage(out, "Invalid action");
        }
    }

    private void generateControlPage(PrintWriter out, String message) {
        out.println("<!DOCTYPE html>");
        out.println("<html>");
        out.println("<head><title>IoT Device Control</title></head>");
        out.println("<body>");
        out.println("<h2>Device Control Panel</h2>");
        out.println("<p style='color:red;'>" + message + "</p>");
        out.println("<form method='post' action='device/control'>");
        out.println("Sensor Name: <input type='text' name='sensorName'><br>");
        out.println("Sensor Value: <input type='text' name='sensorValue'><br>");
        out.println("<input type='hidden' name='action' value='addSensor'>");
        out.println("<input type='submit' value='Add Sensor'>");
        out.println("</form>");
        out.println("</body></html>");
    }

    private void generateDataPage(PrintWriter out) {
        out.println("<!DOCTYPE html>");
        out.println("<html>");
        out.println("<head><title>Sensor Data</title></head>");
        out.println("<body>");
        out.println("<h2>Sensor Readings</h2>");
        out.println("<table border='1'>");
        out.println("<tr><th>Sensor Name</th><th>Value</th></tr>");
        
        // 危险：直接输出用户输入内容，未进行HTML转义
        for (SensorData data : sensorList) {
            out.println("<tr><td>" + data.getName() + "</td>");
            out.println("<td>" + data.getValue() + "</td></tr>");
        }
        
        out.println("</table>");
        out.println("</body></html>");
    }

    class SensorData {
        private String name;
        private String value;

        SensorData(String name, String value) {
            this.name = name;
            this.value = value;
        }

        String getName() { return name; }
        String getValue() { return value; }
    }
}