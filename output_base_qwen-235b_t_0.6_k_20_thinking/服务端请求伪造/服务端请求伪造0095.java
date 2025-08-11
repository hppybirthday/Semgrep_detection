package com.example.ssrf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

@SpringBootApplication
public class SsrfDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Controller
    public static class SsrfController {

        @Autowired
        private RestTemplate restTemplate;

        @GetMapping("/proxy")
        @ResponseBody
        public String proxyRequest(@RequestParam String url, @RequestParam Map<String, String> params) {
            try {
                // 元编程特性：动态构建URI
                URI targetUri = UriComponentsBuilder.fromHttpUrl(url)
                    .queryParam("token", "internal_api_key_12345")
                    .buildAndExpand(params)
                    .encode()
                    .toUri();

                // 存在漏洞的请求转发
                return restTemplate.getForObject(targetUri, String.class);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }

        // 模拟业务接口：获取第三方数据
        @GetMapping("/getExternalData")
        @ResponseBody
        public String getExternalData(@RequestParam String serviceUrl) {
            String internalUrl = "http://" + serviceUrl + ":8080/api/data";
            return restTemplate.getForObject(internalUrl, String.class);
        }
    }
}