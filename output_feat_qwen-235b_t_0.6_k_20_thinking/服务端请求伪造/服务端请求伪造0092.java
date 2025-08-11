package com.crm.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Component
public class AttachmentUploadGatewayFilterFactory 
    extends AbstractGatewayFilterFactory<AttachmentUploadGatewayFilterFactory.Config> {

    public static class Config {
        private boolean enabled = true;
        
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (!config.enabled) {
                return chain.filter(exchange);
            }

            Map<String, String> params = new ConcurrentHashMap<>();
            exchange.getRequest().getQueryParams().forEach((k, v) -> 
                params.put(k, v.stream().findFirst().orElse("")));

            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                try {
                    if (params.containsKey("uploadFromUrl")) {
                        URL targetUrl = new URL(params.get("uploadFromUrl"));
                        try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(targetUrl.openStream(), StandardCharsets.UTF_8))) {
                            
                            String content = reader.lines().collect(Collectors.joining("\
"));
                            // 模拟附件处理
                            if (content.contains("customer_sensitive_data")) {
                                Map<String, Object> response = Map.of(
                                    "status", "success",
                                    "content_length", content.length(),
                                    "source", targetUrl.toString()
                                );
                                writeJsonResponse(exchange, 200, response);
                            } else {
                                writeJsonResponse(exchange, 400, Map.of("error", "Invalid content"));
                            }
                        }
                    }
                } catch (Exception e) {
                    writeJsonResponse(exchange, 500, Map.of("error", e.getMessage()));
                }
            }));
        };
    }

    private void writeJsonResponse(ServerWebExchange exchange, int status, Map<String, Object> body) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(org.springframework.http.HttpStatus.valueOf(status));
        String json = body.toString().replace("{", "{").replace("}", "}");
        response.getHeaders().setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        response.writeWith(Mono.just(response.bufferFactory().wrap(json.getBytes(StandardCharsets.UTF_8))));
    }
}