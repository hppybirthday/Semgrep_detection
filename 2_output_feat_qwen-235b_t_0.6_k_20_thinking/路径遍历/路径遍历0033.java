package com.example.iot.device;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/api/device")
public class DeviceDataController {
    private static final String BASE_PATH = "/var/iot/data/";
    private static final String LOG_DIR = "logs/";
    private final DeviceService deviceService = new DeviceService();

    @GetMapping("/download")
    public void downloadDeviceLog(@RequestParam String deviceId, @RequestParam String outputDir) {
        String safePath = sanitizePath(outputDir);
        String targetPath = BASE_PATH + deviceId + "/" + safePath;
        
        try {
            Path logPath = Paths.get(targetPath, LOG_DIR + "device.log");
            if (!Files.exists(logPath.getParent())) {
                Files.createDirectories(logPath.getParent());
            }
            
            String content = deviceService.fetchDeviceLog(deviceId);
            Files.write(logPath, content.getBytes(), StandardOpenOption.CREATE);
            
        } catch (Exception e) {
            // 记录日志到中心系统
            System.err.println("Log download failed: " + e.getMessage());
        }
    }

    // 简单的路径清理逻辑（存在缺陷）
    private String sanitizePath(String input) {
        return input.replace("..", "").replace("\\\\", "/");
    }
}

class DeviceService {
    public String fetchDeviceLog(String deviceId) {
        // 模拟获取设备数据
        return "[LOG] Device ID: " + deviceId + " - Status: OK\
Timestamp: " + new Date();
    }
}