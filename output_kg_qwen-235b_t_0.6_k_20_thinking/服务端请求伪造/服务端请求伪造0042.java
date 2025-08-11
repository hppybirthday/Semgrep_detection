package com.example.ssrfdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.stream.Collectors;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class SsrfVulnerableApp {

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }

    @GetMapping("/cleandata")
    public ResponseEntity<String> cleanData(@RequestParam String url) {
        try {
            // SSRF漏洞点：直接使用用户提供的URL
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // 数据清洗操作：转换为大写并过滤空行
            String cleanedData = response.body().lines()
                    .filter(line -> !line.trim().isEmpty())
                    .map(String::toUpperCase)
                    .collect(Collectors.joining("\
"));

            return ResponseEntity.ok(cleanedData);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error processing request: " + e.getMessage());
        }
    }

    // 辅助方法：检查内部IP（未被调用，体现漏洞）
    private boolean isInternalIP(String host) {
        return host.matches("(127\\\\.0\\\\.0\\\\.1)|(10\\\\.\\\\d{1,3}\\\\.\\\\d{1,3}\\\\.\\\\d{1,3})|(172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.\\\\d{1,3}\\\\.\\\\d{1,3})|(192\\\\.168\\\\.\\\\d{1,3}\\\\.\\\\d{1,3})");
    }
}

// 漏洞特征：
// 1. 直接使用用户输入作为HTTP请求的URI
// 2. 未验证URL的主机名是否为内部资源
// 3. 返回原始响应内容给客户端
// 攻击示例：
// /api/cleandata?url=http://localhost:8080/secret-data
// /api/cleandata?url=file:///etc/passwd