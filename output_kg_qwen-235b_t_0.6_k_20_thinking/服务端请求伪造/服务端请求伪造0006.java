package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import java.net.URI;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api/v1/device")
public class IoTDeviceController {
    private final RestTemplate restTemplate = new RestTemplate();

    // 模拟设备状态存储
    private final Map<String, String> deviceStatus = new HashMap<>();

    public IoTDeviceController() {
        // 初始化模拟设备
        deviceStatus.put("temp_sensor_001", "25.5°C");
        deviceStatus.put("humidity_045", "60%");
    }

    @GetMapping("/status")
    public String getDeviceStatus(@RequestParam String deviceId) {
        return deviceStatus.getOrDefault(deviceId, "Device not found");
    }

    @PostMapping("/update")
    public String updateDeviceStatus(@RequestParam String deviceId, 
                                    @RequestParam String value) {
        deviceStatus.put(deviceId, value);
        return "Updated";
    }

    // 存在SSRF漏洞的端点
    @GetMapping("/fetch")
    public String fetchDataFromExternal(@RequestParam String deviceUrl) {
        try {
            // 危险操作：直接使用用户输入的URL
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(deviceUrl), String.class);
            return "Data fetched: " + response.getBody();
        } catch (Exception e) {
            return "Error fetching data: " + e.getMessage();
        }
    }

    // 模拟设备控制接口
    @PostMapping("/control")
    public String controlDevice(@RequestParam String command, 
                              @RequestParam(required = false) String target) {
        if (target == null || target.isEmpty()) {
            return "No target specified";
        }
        
        // 二次请求：可能通过target参数发起SSRF攻击
        if (command.equals("relay")) {
            try {
                ResponseEntity<String> response = restTemplate.getForEntity(new URI(target), String.class);
                return "Relay response: " + response.getBody();
            } catch (Exception e) {
                return "Relay failed: " + e.getMessage();
            }
        }
        
        return "Command executed: " + command;
    }

    // 漏洞利用示例：
    // http://server/api/v1/device/fetch?deviceUrl=http://127.0.0.1:8080/api/v1/device/status?deviceId=temp_sensor_001
    // http://server/api/v1/device/control?command=relay&target=file:///etc/passwd
}