package com.example.mathsim;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

// 领域模型：数学建模配置
public class SimulationConfig {
    private String basePath = "/var/sim_data/";
    
    public String getStoragePath() {
        return basePath + LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy/MM/"));
    }
}

// 应用服务：文件上传服务
class FileUploadService {
    private SimulationConfig config;
    
    public FileUploadService(SimulationConfig config) {
        this.config = config;
    }
    
    // 存在漏洞的文件上传方法
    public void uploadFile(String fileName, byte[] content) throws IOException {
        // 路径拼接漏洞点：直接拼接用户输入
        Path targetPath = Paths.get(config.getStoragePath() + fileName);
        
        // 模拟BladeCodeGenerator调用
        BladeCodeGenerator.run(targetPath.toString(), content);
        
        // 记录上传日志（简化版）
        System.out.println("File uploaded to: " + targetPath);
    }
}

// 基础设施：模拟Blade代码生成器
class BladeCodeGenerator {
    // 模拟文件操作API调用
    public static void run(String path, byte[] content) throws IOException {
        // 实际执行文件写入
        Files.write(Paths.get(path), content);
    }
}

// 应用入口
public class MathModelApplication {
    public static void main(String[] args) {
        try {
            SimulationConfig config = new SimulationConfig();
            FileUploadService service = new FileUploadService(config);
            
            // 模拟用户输入（攻击载荷）
            String userInput = "../../etc/passwd";
            byte[] payload = "root:x:0:0:root:/root:/bin/bash".getBytes();
            
            // 触发漏洞
            service.uploadFile(userInput, payload);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}