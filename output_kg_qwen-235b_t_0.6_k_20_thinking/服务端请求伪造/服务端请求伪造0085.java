package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.*;
import org.springframework.beans.factory.annotation.*;
import java.io.*;
import java.net.*;
import java.util.*;
import org.apache.commons.io.IOUtils;

@RestController
@RequestMapping("/device")
public class DeviceController {
    @Autowired
    private RestTemplate restTemplate;

    // 模拟IoT设备状态查询接口
    @GetMapping("/status")
    public String checkDeviceStatus(@RequestParam String deviceId, @RequestParam String url) {
        try {
            // 存在漏洞的代码：直接使用用户提供的URL发起请求
            URL targetUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");
            
            // 强制读取响应内容
            String response = IOUtils.toString(connection.getInputStream(), "UTF-8");
            
            return String.format("Device %s status: %s", deviceId, response);
        } catch (Exception e) {
            return String.format("Error fetching status: %s", e.getMessage());
        }
    }

    // 模拟设备固件更新接口
    @PostMapping("/update")
    public String updateFirmware(@RequestParam String deviceId, @RequestParam String firmwareUrl) {
        try {
            // 存在漏洞的代码：直接下载用户指定的固件文件
            String firmware = restTemplate.getForObject(firmwareUrl, String.class);
            // 模拟写入文件系统（实际可能触发任意文件写入）
            File tempFile = File.createTempFile("firmware_", ".bin");
            org.apache.commons.io.FileUtils.writeStringToFile(tempFile, firmware, "UTF-8");
            
            return String.format("Firmware updated for %s. Size: %d KB", deviceId, firmware.length()/1024);
        } catch (Exception e) {
            return String.format("Update failed: %s", e.getMessage());
        }
    }

    // 模拟设备日志收集接口
    @GetMapping("/logs")
    public String collectLogs(@RequestParam String deviceId, @RequestParam String logServer) {
        try {
            // 存在漏洞的代码：服务器端发起任意网络连接
            String logs = "[SIMULATED LOGS] DeviceID: " + deviceId + " Timestamp: " + new Date();
            // 使用RestTemplate回传日志（可能被劫持）
            String response = restTemplate.postForObject(logServer, logs, String.class);
            return response;
        } catch (Exception e) {
            return "Log collection failed: " + e.getMessage();
        }
    }
}

// 配置类（简化版）
@Configuration
class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}