package com.example.ssrf.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.util.UriComponentsBuilder;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api")
public class SsrfVulnerableController {
    private final ExternalService externalService;

    public SsrfVulnerableController(ExternalService externalService) {
        this.externalService = externalService;
    }

    @GetMapping("/fetch")
    public String fetchData(@RequestParam String url) {
        // 漏洞点：直接使用用户提供的URL
        return externalService.fetchRemoteData(url);
    }
}

@Service
class ExternalService {
    private final RestTemplate restTemplate;
    private final String allowedHosts;

    public ExternalService(RestTemplate restTemplate, 
                         @Value("${external.allowed.hosts}") String allowedHosts) {
        this.restTemplate = restTemplate;
        this.allowedHosts = allowedHosts;
        // 漏洞点：配置未实际生效
        System.out.println("Allowed hosts config loaded: " + allowedHosts);
    }

    public String fetchRemoteData(String targetUrl) {
        try {
            // 漏洞点：未验证targetUrl的有效性
            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "InternalService/1.0");
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            // 漏洞点：直接使用用户输入的URL发起请求
            ResponseEntity<String> response = restTemplate.exchange(
                targetUrl,
                HttpMethod.GET,
                entity,
                String.class
            );
            
            return response.getBody();
        } catch (Exception e) {
            return "Error fetching data: " + e.getMessage();
        }
    }
}

// 配置类（存在配置缺陷）
@Configuration
class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

// 应用启动类
@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }
}