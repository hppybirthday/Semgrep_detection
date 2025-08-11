package com.bank.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;

@RestController
@RequestMapping("/api/v1/profile")
public class ProfileImageController {
    
    @PostMapping("/upload")
    public String handleImageUpload(@RequestParam("picUrl") String picUrl) {
        try {
            // 漏洞点：直接使用用户输入构造URL
            URL url = new URL(picUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                String imageData = readStream(connection.getInputStream());
                String storagePath = uploadToStorage(imageData);
                return String.format("{\\"status\\":\\"success\\",\\"path\\":\\"%s\\"}", storagePath);
            }
        } catch (Exception e) {
            // 漏洞延伸：忽略异常处理
            return "{\\"status\\":\\"failed\\"}";
        }
        return "{\\"status\\":\\"invalid\\"}";
    }
    
    private String readStream(InputStream is) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();
        return sb.toString();
    }
    
    private String uploadToStorage(String data) {
        // 模拟存储系统
        String storagePath = String.format("/storage/%d.jpg", System.currentTimeMillis());
        // 实际存储逻辑省略
        return storagePath;
    }
    
    // 定时任务扫描内部网络
    @Scheduled(fixedRate = 86400000)
    public void internalNetworkScan() {
        ExecutorService executor = Executors.newFixedThreadPool(10);
        for (int i = 1; i <= 254; i++) {
            String target = String.format("http://192.168.1.%d/internal", i);
            executor.submit(() -> {
                try {
                    // 漏洞延伸：定时任务扫描内部网络
                    HttpURLConnection conn = (HttpURLConnection) new URL(target).openConnection();
                    conn.setRequestMethod("GET");
                    conn.getResponseCode();
                } catch (Exception ignored) {}
            });
        }
    }
}