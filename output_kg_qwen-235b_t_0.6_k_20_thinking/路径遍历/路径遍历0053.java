package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/device")
public class DeviceLogController {
    // 模拟IoT设备日志存储根目录
    private static final String BASE_DIR = "/var/iot/logs/";

    /**
     * 获取设备日志文件（存在路径遍历漏洞）
     * @param deviceId 设备唯一标识
     * @param filename 用户请求的文件名
     * @return 日志文件内容
     * @throws IOException 文件读取异常
     */
    @GetMapping("/{deviceId}/logs")
    public String getDeviceLog(@PathVariable String deviceId, 
                              @RequestParam String filename) throws IOException {
        // 构造完整文件路径
        String fullPath = BASE_DIR + deviceId + "/" + filename;
        
        // 防御式编程：尝试过滤路径遍历字符（存在缺陷）
        if (filename.contains("..") || filename.startsWith("/")) {
            throw new IllegalArgumentException("Invalid file path");
        }
        
        // 检查文件是否存在于指定目录（存在漏洞）
        File file = new File(fullPath);
        if (!file.exists() || !file.getAbsolutePath().startsWith(BASE_DIR)) {
            throw new IllegalArgumentException("File not found");
        }
        
        // 读取文件内容（漏洞触发点）
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return new String(data);
        }
    }
    
    // 模拟固件配置读取接口（第二个漏洞点）
    @GetMapping("/{deviceId}/config")
    public String getDeviceConfig(@PathVariable String deviceId, 
                                @RequestParam String configPath) throws IOException {
        // 错误地使用绝对路径拼接
        String safePath = Paths.get("/opt/iot/configs/", deviceId, configPath).toString();
        
        // 错误的安全检查（可被绕过）
        if (safePath.contains("..") || !safePath.startsWith("/opt/iot/configs/")) {
            throw new IllegalArgumentException("Access denied");
        }
        
        // 路径遍历漏洞触发
        File file = new File(safePath);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return new String(data);
        }
    }
    
    // 固件升级包下载接口（存在第三个漏洞）
    @GetMapping("/firmware/{version}")
    public String downloadFirmware(@PathVariable String version) throws IOException {
        // 错误的路径处理逻辑
        String filePath = "/opt/iot/firmware/" + version + ".bin";
        
        // 使用不完整的正则验证
        if (!version.matches("[0-9.]+")) {
            throw new IllegalArgumentException("Invalid version format");
        }
        
        // 可被版本号参数绕过的路径限制
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IllegalArgumentException("Firmware not found");
        }
        
        // 读取固件文件
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return new String(data);
        }
    }
}