package com.example.iot.controller;

import com.example.iot.service.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

@RestController
@RequestMapping("/api/device")
public class DeviceController {
    @Autowired
    private DeviceService deviceService;

    @GetMapping("/config")
    public String downloadConfig(@RequestParam String url) {
        try {
            URL targetUrl = new URL(url);
            if (!deviceService.validateUrl(targetUrl)) {
                return "Invalid URL format";
            }

            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return deviceService.readInputStream(connection.getInputStream());
            } else {
                return "Failed to fetch config, response code: " + responseCode;
            }
        } catch (Exception e) {
            return "Error fetching config: " + e.getMessage();
        }
    }
}

package com.example.iot.service;

import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;

@Service
public class DeviceService {
    public boolean validateUrl(URL url) {
        // 简单的URL验证逻辑，仅检查协议类型
        String protocol = url.getProtocol().toLowerCase();
        return protocol.equals("http") || protocol.equals("https");
    }

    public String readInputStream(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        
        reader.close();
        return response.toString();
    }
}

// 配置类（模拟Spring配置）
@Configuration
public class AppConfig {
    // 假设包含其他必要配置
}