package com.example.iot.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceDataController {
    // 基础存储路径（意图限制访问范围）
    private static final String BASE_STORAGE_PATH = "/var/iot/data/";

    @PostMapping("/upload")
    public String handleImageUpload(@RequestParam("folder") String folder,
                                   @RequestParam("file") MultipartFile file) {
        try {
            // 漏洞点：直接拼接用户输入路径
            String safePath = sanitizePath(folder);
            File targetDir = new File(BASE_STORAGE_PATH + safePath);
            
            // 创建存储目录（看似安全的防御措施）
            if (!targetDir.exists() && !targetDir.mkdirs()) {
                return "Directory creation failed";
            }

            // 文件写入操作（存在路径穿越风险）
            File targetFile = new File(targetDir, file.getOriginalFilename());
            try (FileOutputStream fos = new FileOutputStream(targetFile)) {
                fos.write(file.getBytes());
            }

            return "Upload successful to " + targetFile.getAbsolutePath();
            
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }

    // 不充分的路径过滤（存在绕过可能）
    private String sanitizePath(String path) {
        // 错误的过滤逻辑：仅替换一次且可被编码绕过
        return path.replace("../", "");
    }

    // 模拟设备控制接口（受路径漏洞影响）
    @GetMapping("/config")
    public String loadConfig(@RequestParam("device") String deviceId) {
        File configFile = new File(BASE_STORAGE_PATH + "configs/" + deviceId + ".conf");
        // 当路径被篡改时可能读取任意文件
        return configFile.exists() ? "Config loaded" : "Config not found";
    }
}