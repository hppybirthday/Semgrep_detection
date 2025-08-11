package com.example.ssrf.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.reactive.function.client.WebClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.ClientResponse;
import reactor.core.publisher.Mono;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class SsrfVulnerableApplication {
    @Autowired
    private WebClient.Builder webClientBuilder;

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApplication.class, args);
    }

    @RestController
    @RequestMapping("/api")
    public class DynamicProxyController {
        @GetMapping("/proxy")
        public Mono<String> dynamicProxy(@RequestParam String targetUrl) {
            try {
                // 使用反射动态创建WebClient实例
                Class<?> webClientClass = Class.forName("org.springframework.web.reactive.function.client.WebClient");
                Method uriMethod = webClientClass.getMethod("uri", String.class);
                
                // 构造动态代理链
                Object webClientInstance = webClientBuilder.build();
                Object response = uriMethod.invoke(webClientInstance, targetUrl);
                
                Method retrieveMethod = webClientClass.getMethod("retrieve");
                Object clientResponse = retrieveMethod.invoke(response);
                
                Method bodyToMonoMethod = clientResponse.getClass().getMethod("bodyToMono", Class.class);
                return (Mono<String>) bodyToMonoMethod.invoke(clientResponse, String.class);
            } catch (Exception e) {
                return Mono.just("Error: " + e.getMessage());
            }
        }
    }

    // 元编程风格的配置类
    @Component
    public class DynamicConfig {
        private final Map<String, Object> configStore = new HashMap<>();

        public DynamicConfig() {
            // 模拟动态配置注入
            configStore.put("proxy.timeout", 5000);
            configStore.put("proxy.retry", 3);
        }

        public Object getConfig(String key) {
            return configStore.get(key);
        }
    }

    // 模拟元编程风格的客户端定制器
    @Bean
    public WebClientCustomizer webClientCustomizer() {
        return webClientBuilder -> {
            // 动态添加过滤器
            webClientBuilder.filters(exchangeFilterFunctions -> {
                exchangeFilterFunctions.add((request, next) -> {
                    // 动态处理请求头
                    return next.exchange(request);
                });
            });
        };
    }
}