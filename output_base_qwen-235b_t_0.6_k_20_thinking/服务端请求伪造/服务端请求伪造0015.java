package com.example.ssrfdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.lang.reflect.Method;
import java.net.URI;

@SpringBootApplication
public class SsrfDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @RestController
    public static class ConfigController {

        @GetMapping("/config")
        public String getConfig(@RequestParam String source) {
            try {
                // 使用元编程动态调用配置获取方法
                Class<?> configServiceClass = Class.forName("com.example.ssrfdemo.ConfigService");
                Object configService = configServiceClass.getDeclaredConstructor().newInstance();
                Method method = configServiceClass.getMethod("fetchConfig", String.class);
                
                // 直接拼接用户输入导致SSRF漏洞
                String url = "http://config-server:8080/api/v1/config?file=" + source;
                return (String) method.invoke(configService, url);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    public static class ConfigService {
        private final RestTemplate restTemplate;

        public ConfigService(RestTemplate restTemplate) {
            this.restTemplate = restTemplate;
        }

        public String fetchConfig(String url) {
            // 危险的实现：直接使用用户控制的URL
            return restTemplate.getForObject(URI.create(url), String.class);
        }
    }
}