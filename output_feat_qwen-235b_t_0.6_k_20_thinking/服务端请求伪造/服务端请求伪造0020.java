package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.logging.Logger;

@SpringBootApplication
public class SsrfVulnerableApp {
    private static final Logger logger = Logger.getLogger(SsrfVulnerableApp.class.getName());
    
    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }
    
    @Controller
    public static class ImageController {
        private final RestTemplate restTemplate = new RestTemplate();
        
        @GetMapping("/process-image")
        public String processImage(@RequestParam String imageUri) {
            try {
                // 漏洞点：直接使用用户输入的URI发起请求
                ResponseEntity<String> response = restTemplate.getForEntity(new URI(imageUri), String.class);
                
                // 日志记录（可能包含敏感响应）
                logDetailCat("Image content: " + response.getBody());
                return "Image processed successfully";
            } catch (Exception e) {
                logKill("Error processing image: " + e.getMessage());
                return "Error processing image";
            }
        }
        
        private void logDetailCat(String content) {
            // 模拟HTML转义处理
            String safeContent = content.replace("<", "&lt;").replace(">", "&gt;");
            logger.info("[logDetailCat] " + safeContent);
        }
        
        private void logKill(String error) {
            // 模拟错误信息返回
            if (error.contains("404")) {
                logger.severe("[logKill] Resource not found");
            } else {
                logger.severe("[logKill] " + error);
            }
        }
    }
    
    // 模拟配置类
    public static class ExecutorBiz {
        private String executorAddress;
        
        public ExecutorBiz(String executorAddress) {
            this.executorAddress = executorAddress;
        }
        
        public void executeTask() throws IOException {
            // 漏洞利用链：executorAddress可能被污染
            Process process = Runtime.getRuntime().exec("curl " + executorAddress);
            process.waitFor();
        }
    }
}