package com.example.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

@SpringBootApplication
public class SsrfVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }
}

@RestController
class ServiceInvokerController {
    private final RestTemplate restTemplate;

    public ServiceInvokerController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/invoke")
    public String invokeService(@RequestParam String serviceUrl, @RequestParam Map<String, String> params) {
        try {
            // 元编程特性：动态构建URI
            URI targetUri = UriComponentsBuilder.fromUriString(serviceUrl)
                    .buildAndExpand(params)
                    .encode()
                    .toUri();

            // 直接使用用户输入的URL发起请求（存在SSRF漏洞）
            ResponseEntity<String> response = restTemplate.getForEntity(targetUri, String.class);
            
            return "Response Status: " + response.getStatusCodeValue() + "\
" + 
                   "Response Body: " + response.getBody();
        } catch (Exception e) {
            return "Error occurred: " + e.getMessage();
        }
    }

    // 模拟微服务注册中心元数据
    @GetMapping("/metadata")
    public String getMetadata() {
        return "{\\"internal-services\\":[\\"http://config-service:8888\\",\\"http://discovery:8761\\"]}";
    }
}