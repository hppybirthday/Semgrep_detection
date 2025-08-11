package com.example.ssrfdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

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
class NotificationController {
    private final NotificationService notificationService;

    public NotificationController(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @PostMapping("/notify")
    public ResponseEntity<String> handleNotification(@RequestBody NotificationRequest request) {
        try {
            String response = notificationService.sendNotification(request);
            return ResponseEntity.ok("Response: " + response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
}

@Service
class NotificationService {
    private final RestTemplate restTemplate;

    public NotificationService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String sendNotification(NotificationRequest request) {
        // 漏洞点：直接使用用户提供的URL参数发起请求
        URI uri = UriComponentsBuilder.fromHttpUrl(request.getNotifyUrl()).build().toUri();
        ResponseEntity<Map> response = restTemplate.getForEntity(uri, Map.class);
        return response.getBody().toString();
    }
}

record NotificationRequest(String notifyUrl) {}
