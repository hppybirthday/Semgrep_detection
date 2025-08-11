package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

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
@RequestMapping("/api/v1")
class VulnerableController {

    private final RestTemplate restTemplate;

    public VulnerableController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @PostMapping("/validate")
    public ResponseEntity<String> validateService(@RequestBody Map<String, Object> request) {
        // 模拟CAS ST验证流程中的漏洞点
        if ("ST-1234567890ABCDE".equals(request.get("ticket"))) {
            String serviceUrl = (String) ((Map<String, Object>) request.get("service")).get("url");
            
            // 危险的URL调用逻辑
            Map<String, Object> metadata = (Map<String, Object>) request.get("metadata");
            Map<String, Object> config = (Map<String, Object>) metadata.get("config");
            
            // 构造恶意请求参数
            String attackParam = "";
            if (config.containsKey("b") && config.containsKey("p")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> params = (Map<String, Object>) config.get("params");
                attackParam = "?param[]=" + params.get("key") + 
                            "&b[]=" + ((String[]) config.get("b"))[2] + 
                            "&p[]=" + ((String[]) config.get("p"))[2];
            }

            // 直接使用用户提供的URL进行内部请求
            String fullUrl = serviceUrl + attackParam;
            String response = restTemplate.postForObject(fullUrl, null, String.class);
            
            return ResponseEntity.ok("{\\"status\\":\\"success\\",\\"data\\":\\"" + response + "\\"}");
        }
        return ResponseEntity.badRequest().body("{\\"status\\":\\"error\\",\\"message\\":\\"Invalid ticket\\"}");
    }
}