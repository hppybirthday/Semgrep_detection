package com.example.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@SpringBootApplication
@RestController
@RequestMapping("/image")
public class SsrfVulnerableApp {
    private final RestTemplate restTemplate = new RestTemplate();

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }

    @GetMapping("/fetch")
    public String fetchImage(@RequestParam String url) {
        try {
            // 漏洞点：直接使用用户提供的URL发起请求
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(url), String.class);
            return "Image content: " + response.getBody();
        } catch (Exception e) {
            return "Error fetching image: " + e.getMessage();
        }
    }

    // 模拟一个内部API端点
    @GetMapping("/internal/secret")
    public String internalSecret() {
        return "INTERNAL_SECRET_DATA_12345";
    }
}

// 编译运行后可通过以下方式触发漏洞：
// http://localhost:8080/image/fetch?url=http://localhost:8080/image/internal/secret
// http://localhost:8080/image/fetch?url=http://internal-db-server:3306