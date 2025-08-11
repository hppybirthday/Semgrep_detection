package com.example.ssrf.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@SpringBootApplication
@EnableFeignClients
public class SsrfVulnerableApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApplication.class, args);
    }

    @RestController
    @RequestMapping("/api")
    public class ExternalServiceController {
        private final ExternalServiceClient externalServiceClient;

        public ExternalServiceController(ExternalServiceClient externalServiceClient) {
            this.externalServiceClient = externalServiceClient;
        }

        @GetMapping("/fetch")
        public Map<String, Object> fetchExternalData(@RequestParam String url) {
            // 漏洞点：直接使用用户提供的URL进行外部请求
            return externalServiceClient.getData(url);
        }
    }

    @FeignClient(name = "external-service-client")
    interface ExternalServiceClient {
        @GetMapping
        Map<String, Object> getData(@RequestParam("url") String url);
    }
}