package com.example.mobileapp;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.function.Function;

@RestController
@RequestMapping("/api/images")
public class ImageController {
    private final WebClient webClient;

    public ImageController(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    @GetMapping("/metadata")
    public Mono<String> getImageMetadata(@RequestParam String imageUrl) {
        // 使用函数式编程风格处理HTTP请求
        Function<String, Mono<String>> fetchMetadata = url -> webClient
            .get()
            .uri(url)
            .retrieve()
            .bodyToMono(String.class)
            .onErrorReturn("Error fetching metadata");

        // 漏洞点：直接使用用户输入的URL进行请求
        return fetchMetadata.apply(imageUrl)
            .map(response -> "Image metadata: " + response);
    }

    // 模拟图片处理服务
    @GetMapping("/process")
    public Mono<String> processImage(@RequestParam String imageUrl, @RequestParam String operation) {
        return webClient
            .get()
            .uri(uriBuilder -> uriBuilder
                .scheme("http")
                .host("image-processor.internal")
                .path("/process")
                .queryParam("url", imageUrl)
                .queryParam("operation", operation)
                .build())
            .retrieve()
            .bodyToMono(String.class)
            .onErrorReturn("Image processing failed");
    }

    // 内部健康检查接口（模拟内部服务）
    @GetMapping("/internal/health")
    private String internalHealthCheck() {
        return "{\\"status\\":\\"healthy\\", \\"secret\\":\\"INTERNAL_API_KEY_123\\"}";
    }
}

// 漏洞配置类（模拟Spring Boot配置）
@Configuration
class WebClientConfig {
    @Bean
    public WebClient webClient() {
        return WebClient.builder()
            .baseUrl("http://external-api.com")
            .build();
    }
}