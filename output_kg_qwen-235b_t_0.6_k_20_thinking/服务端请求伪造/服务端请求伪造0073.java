package com.example.vulnerableapp;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.logging.Logger;

@Controller
public class DataCleaner {
    private static final Logger logger = Logger.getLogger(DataCleaner.class.getName());
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return "Error: Empty file";
        }

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(file.getInputStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                // 模拟解析CSV文件中的URL字段
                String[] parts = line.split(",");
                if (parts.length >= 2 && parts[0].trim().equals("url")) {
                    String targetUrl = parts[1].trim();
                    
                    // 危险：直接使用用户输入构造请求
                    if (!targetUrl.isEmpty()) {
                        processExternalData(targetUrl);
                    }
                }
            }
            
        } catch (Exception e) {
            logger.severe("File processing error: " + e.getMessage());
            return "Error processing file";
        }
        
        return "Data cleaning completed";
    }

    private void processExternalData(String url) {
        try {
            // 漏洞点：未验证目标URL
            HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(url))
                .timeout(java.time.Duration.ofSeconds(10))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            // 模拟数据清洗操作
            if (response.statusCode() == 200) {
                cleanAndStoreData(response.body());
            }
            
        } catch (Exception e) {
            logger.warning("External request failed: " + e.getMessage());
        }
    }

    private void cleanAndStoreData(String rawData) {
        // 简单的模拟数据清洗
        String cleanedData = rawData.replaceAll("[\\x00-\\x1F]", "");
        // 实际存储逻辑被简化
        logger.info("Stored cleaned data length: " + cleanedData.length());
    }
}