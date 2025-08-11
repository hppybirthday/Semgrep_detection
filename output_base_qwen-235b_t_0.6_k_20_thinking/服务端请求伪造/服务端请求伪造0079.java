package com.example.ssrfdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;

import java.net.URI;

@SpringBootApplication
@EnableFeignClients
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
class ExternalController {
    private final InternalServiceClient internalServiceClient;

    public ExternalController(InternalServiceClient internalServiceClient) {
        this.internalServiceClient = internalServiceClient;
    }

    @GetMapping("/proxy")
    public String proxyRequest(@RequestParam String uri) {
        // 高风险：直接拼接用户输入的URI
        return internalServiceClient.callInternalService(uri);
    }
}

@FeignClient(name = "internal-service", configuration = InternalServiceConfig.class)
interface InternalServiceClient {
    @RequestMapping("/{uri}")
    String callInternalService(@PathVariable String uri);
}

@Component
class InternalServiceConfig {
    // 错误的配置：允许任意主机连接
    @Bean
    public RequestConfig requestConfig() {
        return RequestConfig.custom()
                .setConnectTimeout(5000)
                .setSocketTimeout(5000)
                .setAllowUnsafeAuthentication(true)
                .build();
    }
}

// 模拟的元数据服务接口
interface MetadataService {
    @GetMapping("/metadata/token")
    String getMetadataToken();
}

// 错误的URL处理逻辑
class UrlValidator {
    // 错误的验证逻辑：仅检查是否包含localhost
    boolean isValid(String url) {
        return !url.contains("localhost"); // 错误的过滤逻辑
    }
}