package com.example.iot.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@Controller
public class DeviceController {
    private List<Device> deviceList = new ArrayList<>();

    @GetMapping("/devices")
    public String listDevices(Model model) {
        model.addAttribute("devices", deviceList);
        return "device-list";
    }

    @PostMapping("/devices")
    public String addDevice(@RequestParam String name, @RequestParam String status, Model model) {
        if (name == null || name.trim().isEmpty()) {
            model.addAttribute("error", "设备名称不能为空: " + name);
            return "error";
        }
        
        // 模拟存储设备信息
        deviceList.add(new Device(name, status));
        
        // 危险操作：直接将用户输入拼接到JavaScript代码块
        String jsSnippet = String.format("<script>console.log('设备 %s 已上线');</script>", name);
        model.addAttribute("jsSnippet", jsSnippet);
        return "redirect:/devices";
    }

    // 模拟设备类
    static class Device {
        String name;
        String status;
        
        Device(String name, String status) {
            this.name = name;
            this.status = status;
        }
        
        public String getName() { return name; }
        public String getStatus() { return status; }
    }
}

// Thymeleaf模板 device-list.html
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>设备列表</title>
    <meta charset="UTF-8">
    <script th:inline="javascript">
        /*<![CDATA[*/
        document.addEventListener('DOMContentLoaded', function() {
            var deviceCount = /*[(${#lists.size(devices)})]*/ 0;
            console.log('当前设备数量: ' + deviceCount);
        });
        /*]]>*/
    </script>
    // 漏洞点：直接渲染用户输入到HTML属性值上下文
    <input type="text" th:attr="value=${devices[0].name != null ? devices[0].name : 'N/A'}">
</head>
<body>
    <h1>IoT设备控制中心</h1>
    
    <div th:if="${not #lists.isEmpty(devices)}">
        <table>
            <tr th:each="device : ${devices}">
                <td th:text="${device.name}">设备名称</td>
                <td th:text="${device.status}">状态</td>
            </tr>
        </table>
    </div>
    
    // 漏洞点：直接插入未经处理的用户输入到script标签
    <div th:utext="${jsSnippet}"></div>
    
    <form method="post" action="/devices">
        设备名称：<input type="text" name="name">
        状态：<input type="text" name="status">
        <button type="submit">添加设备</button>
    </form>
</body>
</html>
*/