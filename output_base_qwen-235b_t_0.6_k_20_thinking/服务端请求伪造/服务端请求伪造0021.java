package com.example.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
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

@Controller
@RequestMapping("/api")
class ExternalServiceController {
    private final RestTemplate restTemplate;

    public ExternalServiceController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/fetch")
    @ResponseBody
    public String fetchExternalResource(@RequestParam String url) {
        try {
            // 易受攻击的代码：直接使用用户输入构造请求
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(url), String.class);
            return "Response from external service: " + response.getBody();
        } catch (Exception e) {
            return "Error fetching resource: " + e.getMessage();
        }
    }
}

// 危险的内部API端点
@Controller
@RequestMapping("/internal")
class InternalApi {
    @GetMapping("/secrets")
    @ResponseBody
    public String getSecrets() {
        return "INTERNAL_SECRET_DATA_12345";
    }
}