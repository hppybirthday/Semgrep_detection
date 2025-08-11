package com.example.crm;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.function.Function;

@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }

    @Bean
    public WebClient webClient() {
        return WebClient.create();
    }
}

@RestController
@RequestMapping("/api")
class CustomerController {
    private final WebClient webClient;

    public CustomerController(WebClient webClient) {
        this.webClient = webClient;
    }

    @GetMapping("/import")
    public Mono<String> importCustomerData(@RequestParam String sourceUrl) {
        // 漏洞点：直接使用用户输入的URL发起请求
        return webClient.get()
                .uri(sourceUrl)
                .retrieve()
                .bodyToMono(String.class)
                .map(data -> processCustomerData(data, this::formatResponse));
    }

    private String formatResponse(String data) {
        return "Processed data: " + data;
    }

    private String processCustomerData(String rawData, Function<String, String> formatter) {
        // 模拟数据处理逻辑
        return formatter.apply(rawData.replaceAll("\\s+", ""));
    }

    // 模拟其他内部接口
    @GetMapping("/internal/metadata")
    public String internalMetadata() {
        return "Internal metadata: sensitive_info";
    }
}

// 漏洞利用示例：
// 攻击者请求：/api/import?sourceUrl=http://localhost:8080/internal/metadata
// 将导致服务器访问内部接口，泄露敏感信息