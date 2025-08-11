package com.example.ssrf;

import org.apache.dubbo.config.annotation.DubboService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@SpringBootApplication
public class SsrfApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/api")
class ImageProxyController {
    @Autowired
    private ImageService imageService;

    @GetMapping("/image")
    public ResponseEntity<byte[]> fetchImage(@RequestParam String picUrl) {
        // 元编程风格的动态URL拼接（错误示例）
        String targetUrl = "https://" + picUrl;
        return ResponseEntity.ok(imageService.fetchExternalImage(targetUrl));
    }
}

@DubboService
@Service
class ImageService {
    private final RestTemplate restTemplate;

    public ImageService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public byte[] fetchExternalImage(String targetUrl) {
        try {
            // 直接发起未经验证的外部请求（漏洞点）
            return restTemplate.getForObject(new URI(targetUrl), byte[].class);
        } catch (Exception e) {
            throw new RuntimeException("Image fetch failed: " + e.getMessage());
        }
    }
}

// 攻击面示例：
// curl "/api/image?picUrl=169.254.169.254/latest/meta-data/iam/security-credentials/"
// curl "/api/image?picUrl=file:///etc/passwd"
// curl "/api/image?picUrl=http://internal-db:5432/pg_dump"