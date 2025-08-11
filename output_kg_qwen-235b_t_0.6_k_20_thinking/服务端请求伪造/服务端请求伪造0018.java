package com.example.chatapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@SpringBootApplication
public class ChatApplication {
    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/api")
class ChatController {
    private final RestTemplate restTemplate;

    public ChatController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/preview")
    public String previewImage(@RequestParam String imageUrl) {
        try {
            // 漏洞点：直接使用用户输入的URL
            URI uri = new URI(imageUrl);
            String response = restTemplate.getForObject(uri, String.class);
            return "Image content: " + response.substring(0, Math.min(100, response.length())) + "...";
        } catch (URISyntaxException | IOException e) {
            return "Invalid image URL";
        }
    }

    @PostMapping("/send")
    public String sendMessage(@RequestParam String message) {
        // 模拟消息发送逻辑
        if (message.contains("http://") || message.contains("https://")) {
            // 自动预览图片链接
            return previewImage(message.split(" ")[0]);
        }
        return "Message sent: " + message;
    }
}