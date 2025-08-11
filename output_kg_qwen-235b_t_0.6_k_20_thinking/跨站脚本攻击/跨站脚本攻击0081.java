package com.example.iot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class IotXssDemo {
    public static void main(String[] args) {
        SpringApplication.run(IotXssDemo.class, args);
    }
}

@Controller
class DeviceController {
    private List<String> devices = new ArrayList<>();

    @GetMapping("/addDevice")
    public String addDevice(@RequestParam String name, Model model) {
        // 模拟设备注册
        devices.add(name);
        model.addAttribute("deviceName", name);
        return "deviceAdded";
    }

    @GetMapping("/deviceList")
    public String listDevices(Model model) {
        // 直接传递原始设备名称列表
        model.addAttribute("devices", devices);
        return "deviceList";
    }
}

// templates/deviceAdded.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Device Added</title></head>
// <body>
// <h1>Device [[${deviceName}]] added successfully!</h1>
// <p><a href="/deviceList">View all devices</a></p>
// </body>
// </html>

// templates/deviceList.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>Device List</title></head>
// <body>
// <h1>Registered Devices:</h1>
// <ul>
// <li th:each="device : ${devices}" th:text="${device}"></li>
// </ul>
// </body>
// </html>