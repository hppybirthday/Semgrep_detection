package com.example.iot.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceController {
    @Autowired
    private RestTemplate restTemplate;

    // 模拟设备数据采集接口（SSRF漏洞点）
    @GetMapping("/data")
    public String getDeviceData(@RequestParam String deviceUrl) {
        String targetUrl = "http://" + deviceUrl + "/sensor/data";
        ResponseEntity<String> response = restTemplate.getForEntity(targetUrl, String.class);
        return response.getBody();
    }

    // 模拟设备控制接口（SSRF漏洞点）
    @PostMapping("/control")
    public String controlDevice(@RequestParam String cmd, @RequestParam String deviceIp) {
        String targetUrl = "http://" + deviceIp + "/api/ctrl?cmd=" + cmd;
        ResponseEntity<String> response = restTemplate.getForEntity(targetUrl, String.class);
        return response.getBody();
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