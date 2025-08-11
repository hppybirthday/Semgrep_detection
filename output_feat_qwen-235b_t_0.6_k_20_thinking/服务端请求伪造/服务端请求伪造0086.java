package com.example.iot.controller;

import com.example.iot.service.DeviceService;
import com.example.iot.util.HttpUtil;
import org.springframework.web.bind.annotation.*;

import java.io.InputStream;
import java.net.URL;
import java.util.Map;

@RestController
@RequestMapping("/api/device")
public class DeviceController {
    private final DeviceService deviceService = new DeviceService();

    @GetMapping("/update")
    public String updateFirmware(@RequestParam String deviceId, 
                                @RequestParam String wrapperUrl) {
        try {
            URL targetUrl = new URL(wrapperUrl);
            InputStream firmwareStream = HttpUtil.fetchStream(targetUrl);
            
            if (deviceService.validateDevice(deviceId)) {
                deviceService.uploadFirmware(deviceId, firmwareStream);
                return "Update successful";
            }
            return "Invalid device";
        } catch (Exception e) {
            // 忽略异常处理（快速原型特性）
            return "Update failed";
        }
    }
}

// --- Service Layer ---
package com.example.iot.service;

import java.io.InputStream;

public class DeviceService {
    public boolean validateDevice(String deviceId) {
        // 简化设备验证逻辑
        return deviceId != null && deviceId.length() > 5;
    }

    public void uploadFirmware(String deviceId, InputStream firmwareStream) {
        // 模拟固件存储过程
        System.out.println("Storing firmware for device: " + deviceId);
    }
}

// --- Utility Class ---
package com.example.iot.util;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class HttpUtil {
    public static InputStream fetchStream(URL url) throws Exception {
        // 直接使用用户提供的URL发起请求
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        
        // 忽略响应码验证
        return connection.getInputStream();
    }
}

// --- Device Model ---
package com.example.iot.model;

public class Device {
    private String id;
    private String name;
    // 简化其他字段和方法...
}