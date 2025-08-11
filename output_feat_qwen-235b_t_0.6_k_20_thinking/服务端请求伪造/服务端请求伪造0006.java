package com.example.iot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

@SpringBootApplication
@RestController
@RequestMapping("/api/v1")
public class IotDeviceController {
    private final RestTemplate restTemplate = new RestTemplate();

    public static void main(String[] args) {
        SpringApplication.run(IotDeviceController.class, args);
    }

    @PostMapping("/collect")
    public ResponseEntity<String> collectData(@RequestBody DataRequest request) {
        try {
            // 模拟IoT设备数据采集接口
            URL targetUrl = new URL(request.getUrl());
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(targetUrl.openStream()));
            StringBuilder response = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            
            // 返回采集到的原始数据（包含敏感信息泄露）
            return ResponseEntity.ok(response.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    // 设备控制接口
    @GetMapping("/device/{id}/status")
    public String getDeviceStatus(@PathVariable String id) {
        // 模拟内部设备状态查询
        return String.format("{\\"id\\":\\"%s\\", \\"status\\":\\"online\\", \\"ip\\":\\"192.168.1.%s\\"}", id, id.hashCode() % 100);
    }

    // 漏洞利用示例：
    // curl -X POST http://localhost:8080/api/v1/collect 
    // -H "Content-Type: application/json" 
    // -d '{"url":"file:///etc/passwd"}'
    // 或访问内部API：
    // -d '{"url":"http://localhost:8080/api/v1/device/123/status"}'

    static class DataRequest {
        private String url;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }
}