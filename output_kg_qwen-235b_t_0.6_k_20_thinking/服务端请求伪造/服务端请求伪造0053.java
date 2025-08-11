package com.example.ssrf.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SSRFController {
    
    @Autowired
    private SSRFService ssrfService;

    @GetMapping("/fetch")
    public ResponseEntity<String> fetchExternalResource(@RequestParam String url) {
        try {
            String result = ssrfService.fetchExternalData(url);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching resource: " + e.getMessage());
        }
    }
}

class SSRFService {
    
    private final RestTemplate restTemplate = new RestTemplate();

    public String fetchExternalData(String targetUrl) {
        // 模拟业务逻辑：记录日志、添加请求头等
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "CorporateInternalService/1.0");
        
        // 漏洞点：直接使用用户输入的URL发起请求
        // 未进行任何白名单校验或危险协议过滤
        ResponseEntity<String> response = restTemplate.getForEntity(targetUrl, String.class);
        
        // 模拟数据处理逻辑
        if (response.getStatusCode().is2xxSuccessful()) {
            return "Successfully retrieved data: " + response.getBody();
        }
        return "Failed with status code: " + response.getStatusCodeValue();
    }
}

// 模拟配置类
@Configuration
class AppConfig {
    // 实际生产环境可能包含更多配置
}

// 模拟Spring Boot启动类
@SpringBootApplication
public class SsrfApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfApplication.class, args);
    }
}