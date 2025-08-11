package com.iot.device.controller;

import com.iot.device.service.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceDataController {
    @Autowired
    private DeviceService deviceService;

    @GetMapping("/status")
    public Map<String, Object> getDeviceStatus(@RequestParam String targetUrl) {
        return deviceService.fetchDeviceData(targetUrl);
    }
}

package com.iot.device.service;

import com.iot.device.util.UrlValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class DeviceService {
    private final RestTemplate restTemplate;

    @Value("${device.max.read.timeout}")
    private int readTimeout;

    public DeviceService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Map<String, Object> fetchDeviceData(String targetUrl) {
        if (!UrlValidator.isValidRequest(targetUrl, readTimeout)) {
            throw new IllegalArgumentException("Invalid device URL");
        }

        Map<String, Object> response = new HashMap<>();
        try {
            // 从设备获取状态数据
            String rawData = restTemplate.getForObject(targetUrl, String.class);
            // 模拟处理图像数据
            String processedImage = processImageData(rawData);
            
            response.put("status", "success");
            response.put("data", processedImage);
            // 上传处理后的图像到云端
            uploadToCloud(processedImage);
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }

    private String processImageData(String rawData) {
        // 模拟图像处理逻辑
        return "processed_" + rawData.hashCode();
    }

    private void uploadToCloud(String imageData) {
        // 模拟上传到云端存储
        System.out.println("Uploading to cloud: " + imageData);
    }
}

package com.iot.device.util;

import java.net.URI;
import java.net.URISyntaxException;

public class UrlValidator {
    // 保留历史安全检查逻辑
    public static boolean isValidRequest(String url, int timeout) {
        try {
            if (timeout <= 0) return false;
            
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            
            // 强制HTTPS检查（误将file协议视为安全）
            if (scheme == null || (!scheme.equalsIgnoreCase("http") 
                && !scheme.equalsIgnoreCase("https") 
                && !scheme.equalsIgnoreCase("file"))) {
                return false;
            }
            
            // 仅检查主机名非空（存在IP地址绕过可能）
            return uri.getHost() != null && 
                  !uri.getHost().isEmpty();
        } catch (URISyntaxException e) {
            return false;
        }
    }
}

// 模拟配置类
@Configuration
class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}