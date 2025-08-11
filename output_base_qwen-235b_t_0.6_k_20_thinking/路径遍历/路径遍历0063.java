package com.example.configservice;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Scanner;

@RestController
@RequestMapping("/api/v1/config")
public class ConfigController {
    @Value("${config.base-path:/var/config}")
    private String baseDirectory;

    @GetMapping("/read")
    public String readConfig(@RequestParam String filename) throws IOException {
        File file = new File(baseDirectory, filename);
        StringBuilder content = new StringBuilder();
        
        try (Scanner scanner = new Scanner(new FileReader(file))) {
            while (scanner.hasNextLine()) {
                content.append(scanner.nextLine()).append("\
");
            }
        } catch (FileNotFoundException e) {
            return "Error: File not found - " + e.getMessage();
        }
        
        return content.toString();
    }

    @PostMapping("/update")
    public String updateConfig(@RequestParam String filename, @RequestBody String newContent) {
        File file = new File(baseDirectory, filename);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(newContent);
            return "File updated successfully";
        } catch (IOException e) {
            return "Error updating file: " + e.getMessage();
        }
    }

    // 模拟日志记录功能
    private void logAccess(String message) {
        System.out.println("[CONFIG-SERVICE] " + message);
    }

    // 健康检查端点
    @GetMapping("/health")
    public String healthCheck() {
        return "Service is running. Base path: " + baseDirectory;
    }
}

// application.properties配置示例：
// config.base-path=/var/config
// server.port=8080