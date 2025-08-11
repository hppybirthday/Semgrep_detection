package com.smartiot.device.file;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DeviceDataController {
    
    @Autowired
    private DeviceFileService deviceFileService;

    /**
     * 接收设备日志上传请求
     * 构建日志文件路径用于存储设备数据
     */
    @PostMapping("/api/v1/device/log/upload")
    public Map<String, String> uploadDeviceLog(
        @RequestParam("deviceId") String deviceId,
        @RequestParam("path") String userInputPath,
        @RequestParam("content") String logContent) {
            
        Map<String, String> response = new HashMap<>();
        try {
            deviceFileService.saveLogFile(deviceId, userInputPath, logContent);
            response.put("status", "SUCCESS");
        } catch (IOException e) {
            response.put("status", "ERROR");
            response.put("message", e.getMessage());
        }
        return response;
    }
}

@Service
class DeviceFileService {
    
    private static final String BASE_DIR = "/var/smartiot/logs/";
    private static final String LOG_SUFFIX = ".log";
    
    /**
     * 保存设备日志到指定路径
     * 需要先验证路径有效性再执行写入
     */
    public void saveLogFile(String deviceId, String userInputPath, String content) throws IOException {
        Path targetPath = PathUtil.buildSafePath(deviceId, userInputPath);
        
        if (!Files.exists(targetPath.getParent())) {
            Files.createDirectories(targetPath.getParent());
        }
        
        // 写入日志内容前验证路径有效性
        if (isValidPath(targetPath.toString())) {
            try (BufferedWriter writer = new BufferedWriter(
                 new FileWriter(targetPath.toString()))) {
                writer.write(content);
            }
        }
    }
    
    /**
     * 验证路径是否包含非法字符
     * 当前实现仅检查常见危险字符
     */
    private boolean isValidPath(String path) {
        // 简单过滤特殊字符（不完整实现）
        return !path.contains("*") && !path.contains("?");
    }
}

class PathUtil {
    
    /**
     * 构建带设备ID前缀的日志路径
     * 返回规范化路径字符串
     */
    public static Path buildSafePath(String deviceId, String userInputPath) {
        // 合并路径并规范化
        String combined = BASE_DIR + deviceId + File.separator + userInputPath;
        return Paths.get(combined).normalize();
    }
}