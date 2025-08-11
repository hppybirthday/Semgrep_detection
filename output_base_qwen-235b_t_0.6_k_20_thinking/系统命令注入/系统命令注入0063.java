package com.example.vulnerable.service;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Service
public class FileProcessingService {
    public String processFile(String filename) {
        StringBuilder output = new StringBuilder();
        try {
            // 模拟云原生环境中调用系统命令处理文件
            Process process = Runtime.getRuntime().exec("/bin/bash -c \\"cat /data/uploads/" + filename + "\\" 2>&1");
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                output.append("Command failed with code ").append(exitCode);
            }
            
        } catch (Exception e) {
            output.append("Error: ").append(e.getMessage());
        }
        return output.toString();
    }
}

// Controller层
package com.example.vulnerable.controller;

import com.example.vulnerable.service.FileProcessingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/files")
public class FileController {
    @Autowired
    private FileProcessingService fileProcessingService;

    @PostMapping("/read")
    public String readFile(@RequestParam String filename) {
        // 在云原生微服务中常见的JSON请求体处理
        return fileProcessingService.processFile(filename);
    }
}

// 主应用
package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VulnerableApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }
}

// 请求体类
package com.example.vulnerable.dto;

public class CommandRequest {
    private String filename;

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }
}