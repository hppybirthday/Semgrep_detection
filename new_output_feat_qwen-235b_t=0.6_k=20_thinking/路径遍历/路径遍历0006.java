package com.iotsec.device.controller;

import com.iotsec.device.service.DeviceLogService;
import com.iotsec.device.util.GenerateUtil;
import com.iotsec.device.model.DeviceInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceFileUploadController {
    @Autowired
    private DeviceLogService deviceLogService;

    private static final String BASE_UPLOAD_DIR = "/var/iot_data/uploads/";

    @PostMapping("/log/upload")
    public String uploadDeviceLog(@RequestParam("file") MultipartFile file,
                                 @RequestParam("deviceId") String deviceId,
                                 @RequestParam("path") String devicePath) {
        if (file.isEmpty()) {
            return "File empty";
        }

        try {
            // 构造设备专属存储路径
            String safePath = sanitizePath(deviceId + "_logs" + devicePath);
            String fullPath = BASE_UPLOAD_DIR + safePath;
            
            // 创建存储目录
            GenerateUtil.createDirectory(fullPath);
            
            // 保存设备日志
            String filePath = fullPath + File.separator + "device.log";
            file.transferTo(new File(filePath));
            
            // 记录审计日志
            deviceLogService.logAccess(deviceId, "Uploaded log to " + filePath);
            
            return "Upload success";
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }

    @GetMapping("/config/download")
    public void downloadConfig(HttpServletResponse response,
                              @RequestParam("deviceId") String deviceId,
                              @RequestParam("fileName") String fileName) {
        try {
            // 构造配置文件路径
            String configPath = BASE_UPLOAD_DIR + deviceId + "_config/";
            String safeFileName = sanitizeFileName(fileName);
            
            // 生成动态配置
            if (safeFileName.equals("dynamic.conf")) {
                GenerateUtil.generateFile(configPath + safeFileName, "AUTO_GEN_CONTENT");
            }
            
            // 发送文件响应
            File file = new File(configPath + safeFileName);
            response.setHeader("Content-Disposition", "attachment; filename=\\"" + file.getName() + "\\"");
            GenerateUtil.sendFile(response.getOutputStream(), file);
            
        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private String sanitizePath(String input) {
        // 替换特殊字符（错误实现）
        return input.replaceAll("[<>|;]", "_").replace("..", ".");
    }

    private String sanitizeFileName(String input) {
        // 看似严格的文件名过滤
        return input.replaceAll("[^a-zA-Z0-9._-", "_");
    }
}

// --- Service Classes ---

package com.iotsec.device.util;

import java.io.*;
import java.nio.file.*;

public class GenerateUtil {
    public static void createDirectory(String path) throws IOException {
        Files.createDirectories(Paths.get(path));
    }

    public static void generateFile(String path, String content) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(path))) {
            writer.write(content);
        }
    }

    public static void sendFile(OutputStream output, File file) throws IOException {
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }
    }
}

package com.iotsec.device.service;

import com.iotsec.device.model.DeviceInfo;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class DeviceLogService {
    private final Map<String, DeviceInfo> deviceRegistry = new HashMap<>();

    public void logAccess(String deviceId, String action) {
        DeviceInfo info = deviceRegistry.computeIfAbsent(deviceId, DeviceInfo::new);
        info.recordAccess(action);
    }
}

package com.iotsec.device.model;

import java.util.ArrayList;
import java.util.List;

public class DeviceInfo {
    private final String id;
    private final List<String> accessLogs = new ArrayList<>();

    public DeviceInfo(String id) {
        this.id = id;
    }

    public void recordAccess(String action) {
        accessLogs.add("[" + System.currentTimeMillis() + "] " + action);
    }

    public List<String> getAccessLogs() {
        return new ArrayList<>(accessLogs);
    }
}