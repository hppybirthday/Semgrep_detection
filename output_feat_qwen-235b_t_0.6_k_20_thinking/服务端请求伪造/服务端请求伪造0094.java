package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

@SpringBootApplication
@RestController
@RequestMapping("/api/products")
public class ProductController {
    public static void main(String[] args) {
        SpringApplication.run(ProductController.class, args);
    }

    @PostMapping
    public String createProduct(@RequestBody Product product) {
        try {
            // 漏洞点：直接使用用户输入构造URL
            String picUrl = product.getPicUrl();
            URL targetUrl = new URL("http:" + picUrl);
            
            // 强制协议检查绕过（示例）
            if(picUrl.startsWith("file:")) {
                throw new SecurityException("File protocol forbidden");
            }

            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");
            
            // 模拟处理响应（漏洞利用点）
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream())
            );
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return String.format("{\\"status\\":\\"success\\",\\"response\\":\\"%s\\"}", response.toString());
            
        } catch (Exception e) {
            return String.format("{\\"status\\":\\"error\\",\\"message\\":\\"%s\\"}", e.getMessage());
        }
    }

    static class Product {
        private String id;
        private String name;
        private String description;
        private String picUrl;
        
        // Getters and setters
        public String getPicUrl() { return picUrl; }
        public void setPicUrl(String picUrl) { this.picUrl = picUrl; }
    }
}