package com.example.iot.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequestMapping("/api/v1/devices")
public class DeviceController {
    
    @Autowired
    private RestTemplate restTemplate;
    
    // 模拟设备数据采集接口
    @GetMapping("/sensor/data")
    public String getSensorData(@RequestParam String deviceId, 
                               @RequestParam String url) throws URISyntaxException {
        
        // 漏洞点：直接拼接用户输入的URL
        URI targetUrl = new URI(url);
        
        try {
            // 使用RestTemplate发起外部请求获取传感器数据
            ResponseEntity<String> response = restTemplate.getForEntity(targetUrl, String.class);
            return "Device " + deviceId + " data: " + response.getBody();
        } catch (Exception e) {
            return "Error fetching data: " + e.getMessage();
        }
    }
    
    // 设备状态检查接口
    @GetMapping("/status")
    public String checkStatus(@RequestParam String deviceIp) {
        String internalApi = "http://" + deviceIp + ":8080/api/status";
        
        // 漏洞点：未验证deviceIp参数合法性
        try {
            URI uri = new URI(internalApi);
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            return "Device status: " + response.getBody();
        } catch (URISyntaxException | IOException e) {
            return "Status check failed: " + e.getMessage();
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