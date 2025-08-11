package com.example.ssrf.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SsrfVulnerableController {
    
    private static final Logger logger = LoggerFactory.getLogger(SsrfVulnerableController.class);
    
    @Autowired
    private RestTemplate restTemplate;

    @PostMapping("/fetch-content")
    public ResponseEntity<String> fetchContent(@RequestBody Map<String, String> payload) {
        String targetUrl = payload.get("url");
        
        if (targetUrl == null || targetUrl.isEmpty()) {
            return ResponseEntity.badRequest().body("Missing URL parameter");
        }

        try {
            // 构建完整URI
            URI uri = UriComponentsBuilder.fromUriString(targetUrl).build().toUri();
            
            // 发起外部请求（存在漏洞的关键点）
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            
            logger.info("Fetched content from {} with status {}", targetUrl, response.getStatusCodeValue());
            return ResponseEntity.ok(response.getBody());
        } catch (Exception e) {
            logger.error("Error fetching content from {}: {}", targetUrl, e.getMessage());
            return ResponseEntity.status(500).body("Error fetching content: " + e.getMessage());
        }
    }

    @GetMapping("/test-ssrf")
    public ResponseEntity<String> testSsrf(@RequestParam String url) {
        try {
            // 直接使用用户输入的URL参数（漏洞点）
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            return ResponseEntity.ok("Response size: " + response.getBody().length());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    // 模拟敏感内部接口
    @GetMapping("/internal/secret")
    public ResponseEntity<String> internalSecret() {
        return ResponseEntity.ok("Top Secret Data: AWS_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXX");
    }

    // 模拟元数据服务
    @GetMapping("/latest/meta-data/instance-id")
    public ResponseEntity<String> metadataService() {
        return ResponseEntity.ok("i-0abcdef1234567890");
    }
}