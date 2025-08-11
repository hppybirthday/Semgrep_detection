package com.example.iot.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * IoT设备数据采集控制器
 * 模拟通过HTTP接口获取设备日志文件
 */
public class DeviceDataController {
    // 设备日志存储根目录
    private static final String BASE_DIR = "/var/iot/logs/";

    /**
     * 模拟HTTP接口：获取设备指定日志文件内容
     * @param deviceId 设备ID
     * @param fileName 请求读取的文件名
     * @return Base64编码的文件内容
     */
    public String getFile(String deviceId, String fileName) {
        try {
            // 构造完整文件路径
            String fullPath = BASE_DIR + deviceId + "/" + fileName;
            File file = new File(fullPath);

            // 检查文件是否存在
            if (!file.exists()) {
                return "ERROR: File not found";
            }

            // 读取文件内容并Base64编码
            byte[] fileContent = Files.readAllBytes(file.toPath());
            return Base64.getEncoder().encodeToString(fileContent);
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }

    /**
     * 模拟设备数据采集主流程
     */
    public static void main(String[] args) {
        DeviceDataController controller = new DeviceDataController();
        
        // 示例参数：设备ID和文件名
        String deviceId = "D123456";
        String fileName = "operation.log";
        
        // 正常调用示例
        System.out.println("Normal request:");
        System.out.println(controller.getFile(deviceId, fileName));
        
        // 攻击示例：路径遍历攻击
        System.out.println("\
Path traversal attack:");
        String maliciousFileName = "../../../../etc/passwd";
        System.out.println(controller.getFile(deviceId, maliciousFileName));
    }
}