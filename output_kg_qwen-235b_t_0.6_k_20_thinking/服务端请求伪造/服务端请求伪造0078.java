package com.example.ssrfdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

@SpringBootApplication
public class SsrfVulnerableApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/api")
class ExternalServiceController {
    private final ExternalServiceClient externalServiceClient;

    public ExternalServiceController(ExternalServiceClient externalServiceClient) {
        this.externalServiceClient = externalServiceClient;
    }

    @GetMapping("/proxy")
    public String proxyRequest(@RequestParam String url) {
        try {
            return externalServiceClient.callExternalService(url);
        } catch (Exception e) {
            return "Error occurred: " + e.getMessage();
        }
    }
}

@Service
class ExternalServiceClient {
    private final RestTemplate restTemplate;

    public ExternalServiceClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String callExternalService(String targetUrl) throws URISyntaxException {
        // 漏洞点：直接使用用户输入的URL进行请求
        ResponseEntity<String> response = restTemplate.getForEntity(
            new URI(targetUrl),
            String.class
        );
        
        // 返回原始响应内容给客户端
        return "Response Status: " + response.getStatusCodeValue() + 
               "\
Response Body: " + response.getBody();
    }
}

// 配置类
@Configuration
class ServiceConfig {
    @Bean
    public ExternalServiceClient externalServiceClient(RestTemplate restTemplate) {
        return new ExternalServiceClient(restTemplate);
    }
}