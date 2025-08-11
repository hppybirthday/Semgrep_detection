package com.example.iotdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/api/devices")
public class IotDeviceController {
    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, String> deviceDatabase = new HashMap<>();

    public static void main(String[] args) {
        SpringApplication.run(IotDeviceController.class, args);
    }

    // 模拟设备注册
    @PostMapping("/register")
    public ResponseEntity<String> registerDevice(@RequestParam String id, @RequestParam String name) {
        deviceDatabase.put(id, name);
        return ResponseEntity.ok("Device registered: " + name);
    }

    // 漏洞点：SSRF脆弱的传感器数据获取
    @GetMapping("/sensor/data")
    public ResponseEntity<String> fetchSensorData(@RequestParam String deviceUrl) {
        try {
            // 危险操作：直接使用用户输入构造请求
            URI targetUri = new URI(deviceUrl);
            ResponseEntity<String> response = restTemplate.getForEntity(targetUri, String.class);
            
            // 模拟数据处理
            return ResponseEntity.ok("Raw sensor data: " + response.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching sensor data: " + e.getMessage());
        }
    }

    // 模拟设备控制接口（受内部保护）
    @PostMapping("/control/internal")
    private ResponseEntity<String> internalControlEndpoint(@RequestParam String action) {
        // 实际业务逻辑
        return ResponseEntity.ok("Internal action executed: " + action);
    }

    // 辅助端点：列出已注册设备
    @GetMapping("/list")
    public ResponseEntity<Map<String, String>> listDevices() {
        return ResponseEntity.ok(deviceDatabase);
    }
}

// 启动类和基础配置
// 注意：实际项目应包含配置类和安全设置