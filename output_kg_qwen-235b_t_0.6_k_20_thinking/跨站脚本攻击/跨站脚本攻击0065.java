package com.example.iot.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet("/device")
public class DeviceController extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private List<Device> devices = new ArrayList<>();

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        String action = request.getParameter("action");
        
        if ("register".equals(action)) {
            String deviceName = request.getParameter("name");
            String deviceStatus = request.getParameter("status");
            
            // 模拟存储设备信息（未过滤输入）
            devices.add(new Device(deviceName, deviceStatus));
            
            // 跳转到设备列表页
            request.setAttribute("devices", devices);
            request.getRequestDispatcher("/device-list.jsp").forward(request, response);
            
        } else if ("control".equals(action)) {
            String deviceId = request.getParameter("id");
            String command = request.getParameter("cmd");
            // 模拟设备控制逻辑
            response.getWriter().write("Command '" + command + "' sent to device " + deviceId);
        }
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException {
        doPost(request, response);
    }

    // 模拟设备数据结构
    private static class Device {
        String name;
        String status;
        
        Device(String name, String status) {
            this.name = name;
            this.status = status;
        }
    }
}

// device-list.jsp 内容（模拟）
// <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
// <html><body>
// <h2>设备列表</h2>
// <ul>
// <c:forEach items="${devices}" var="device">
//     <li>设备名称: ${device.name} | 状态: ${device.status}</li>  <!-- 这里存在XSS漏洞 -->
// </c:forEach>
// </ul>
// </body></html>