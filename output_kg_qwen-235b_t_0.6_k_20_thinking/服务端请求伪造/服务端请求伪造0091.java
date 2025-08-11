package com.example.crm.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.function.Function;

@RestController
@RequestMapping("/api/leads")
public class LeadImportController {
    private final WebClient webClient = WebClient.builder().build();

    @GetMapping("/import")
    public Mono<String> importLeads(@RequestParam String url) {
        // 漏洞点：直接使用用户输入的URL发起外部请求
        return webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class)
                .map(response -> "Import successful: " + response)
                .onErrorResume(e -> Mono.just("Import failed: " + e.getMessage()));
    }

    // 模拟函数式业务处理
    private Function<String, Mono<String>> processImport = data -> {
        // 实际业务处理逻辑
        return Mono.just("Processed " + data.length() + " records");
    };

    @GetMapping("/test")
    public Mono<String> testConnection(@RequestParam String host) {
        // 危险的辅助接口：可用于端口扫描或内部服务探测
n        return webClient.get()
                .uri("http://" + host + ":8080/actuator/health")
                .retrieve()
                .bodyToMono(String.class)
                .map(response -> "Test result for " + host + ": " + response);
    }
}