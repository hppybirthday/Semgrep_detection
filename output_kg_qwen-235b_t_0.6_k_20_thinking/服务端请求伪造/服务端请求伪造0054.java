package com.example.iot.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Controller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/device")
public class DeviceController {
    private static final Logger logger = LoggerFactory.getLogger(DeviceController.class);
    
    @Autowired
    private RestTemplate restTemplate;

    // 模拟IoT设备数据采集接口
    @GetMapping("/data")
    public @ResponseBody String getDeviceData(@RequestParam String deviceIp) {
        try {
            // 危险：直接拼接用户输入构造目标URL
            String targetUrl = "http://" + deviceIp + ":8080/sensor/data";
            
            // 记录日志（防御式编程的错误示范：仅记录不验证）
            logger.info("Fetching data from device: {}", targetUrl);
            
            // 发起SSRF请求
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(targetUrl), String.class);
            
            return "Device data: " + response.getBody();
        } catch (Exception e) {
            logger.error("Error fetching device data: {}", e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    // 设备控制接口（存在同样漏洞）
    @PostMapping("/control")
    public @ResponseBody String controlDevice(@RequestParam String deviceIp, @RequestParam String command) {
        try {
            String targetUrl = "http://" + deviceIp + ":8080/device/control?cmd=" + command;
            
            // 模拟设备控制请求
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer internal_token");
            
            // 错误：未限制目标地址范围
            ResponseEntity<String> response = restTemplate.postForEntity(new URI(targetUrl), headers, String.class);
            
            return "Control response: " + response.getBody();
        } catch (Exception e) {
            return "Control failed: " + e.getMessage();
        }
    }

    // 健康检查接口（防御式编程的错误示范）
    @GetMapping("/health")
    public @ResponseBody String checkHealth(@RequestParam String deviceIp) {
        // 错误的防御措施：仅检查是否为空
        if (deviceIp == null || deviceIp.isEmpty()) {
            return "Invalid device IP";
        }
        
        try {
            String targetUrl = "http://" + deviceIp + ":8080/healthz";
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(targetUrl), String.class);
            return "Health status: " + response.getBody();
        } catch (Exception e) {
            return "Health check failed: " + e.getMessage();
        }
    }
}