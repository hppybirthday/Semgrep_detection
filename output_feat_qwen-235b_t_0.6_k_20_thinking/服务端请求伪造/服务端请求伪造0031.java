package com.example.gateway;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
public class ImageProxyGatewayFilterFactory extends AbstractGatewayFilterFactory<ImageProxyGatewayFilterFactory.Config> {
    private final WebClient webClient;

    public ImageProxyGatewayFilterFactory(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String endPoint = request.getQueryParams().getFirst("endPoint");
            String variableEndPoint = request.getQueryParams().getFirst("variableEndPoint");

            if (endPoint == null || variableEndPoint == null) {
                return chain.filter(exchange);
            }

            String targetUrl = String.format("http://%s/%s", endPoint, variableEndPoint);
            
            // 存在SSRF漏洞：直接使用用户输入构造URL
            return webClient.get()
                .uri(URI.create(targetUrl))
                .exchangeToMono(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        // 模拟将图片上传到存储系统
                        return response.bodyToMono(byte[].class)
                            .flatMap(bytes -> {
                                // 实际存储逻辑
                                System.out.println("Uploading image of size: " + bytes.length);
                                return chain.filter(exchange);
                            });
                    } else {
                        // 忽略错误响应
                        System.out.println("Ignoring error response: " + response.statusCode());
                        return chain.filter(exchange);
                    }
                })
                .onErrorResume(ex -> {
                    // 忽略所有异常
                    System.err.println("Error fetching image: " + ex.getMessage());
                    return chain.filter(exchange);
                });
        };
    }

    public static class Config {
        // 配置参数
    }
}

// 应用主类（省略）
// @SpringBootApplication
// public class GatewayApplication { ... }
// 
// 配置示例：
// spring.cloud.gateway.routes[0].id=image-proxy
// spring.cloud.gateway.routes[0].uri=lb://image-service
// spring.cloud.gateway.routes[0].predicates[0]=Path=/api/image/**
// spring.cloud.gateway.routes[0].filters[0]=ImageProxy