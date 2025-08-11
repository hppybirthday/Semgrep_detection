package com.example.ssrfdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/process")
class ImageProcessingController {
    @Autowired
    private RestTemplate restTemplate;

    @PostMapping("/image")
    public String processImage(@RequestBody Map<String, String> payload) {
        try {
            // 使用反射动态调用元编程处理方法
            Method method = ImageProcessor.class.getMethod("downloadAndProcess", String.class);
            ImageProcessor processor = new ImageProcessor(restTemplate);
            
            // 危险的URL拼接（攻击面：permalink参数污染）
            String targetUrl = payload.get("permalink");
            
            // 通过元编程执行实际下载操作
            String result = (String) method.invoke(processor, targetUrl);
            return "Processed: " + result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class ImageProcessor {
    private final RestTemplate restTemplate;

    public ImageProcessor(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    // 元编程驱动的下载方法
    public String downloadAndProcess(String imageUrl) throws IOException {
        ResponseEntity<byte[]> response = restTemplate.getForEntity(URI.create(imageUrl), byte[].class);
        byte[] imageBytes = response.getBody();
        
        // 模拟图片处理
        Path tempFile = Files.createTempFile("image-", ".tmp");
        
        // 直接写入磁盘（SSRF攻击效果：文件写入内部资源）
        try (FileOutputStream fos = new FileOutputStream(tempFile.toFile())) {
            fos.write(imageBytes);
        }
        
        return "Saved to " + tempFile.toString();
    }
}