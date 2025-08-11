package com.example.iot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class XssVulnerableApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApplication.class, args);
    }
}

@RestController
class DeviceController {
    @GetMapping("/device")
    public String showDevice(@RequestParam String deviceName) {
        String html = "<html><body>";
        html += "<h1>Device Name: " + deviceName + "</h1>";
        html += "<p>Sensor Data: 25\u00B0C</p>";
        html += "<script>";
        html += "function updateData() {";
        html += "  document.getElementById('data').innerHTML = '26\u00B0C';";
        html += "}";
        html += "</script>";
        html += "<button onclick=\"updateData()\">Refresh</button>";
        html += "<div id=\"data\">25\u00B0C</div>";
        html += "</body></html>";
        return html;
    }

    @PostMapping("/log")
    public String logData(@RequestParam String data) {
        // 模拟日志记录（实际可能写入数据库或文件）
        System.out.println("[LOG] " + data);
        return "Logged: " + data;
    }
}
