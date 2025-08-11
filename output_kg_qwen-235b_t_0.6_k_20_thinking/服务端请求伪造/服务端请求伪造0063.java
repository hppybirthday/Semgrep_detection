package com.example.ssrfdemo.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;

@Service
public class PaymentService {
    private final RestTemplate restTemplate;

    public PaymentService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String processPayment(String callbackUrl, Map<String, Object> paymentDetails) {
        // 构造支付请求URL（存在漏洞的关键点）
        String paymentUrl = "http://payment-gateway/api/v1/charge?callback=" + callbackUrl;
        
        // 直接使用用户输入的callbackUrl发起请求，未进行任何验证
        return restTemplate.getForObject(URI.create(paymentUrl), String.class);
    }
}

package com.example.ssrfdemo.controller;

import com.example.ssrfdemo.service.PaymentService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class OrderController {
    private final PaymentService paymentService;

    public OrderController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    @PostMapping("/order")
    public String createOrder(@RequestParam String callbackUrl,
                             @RequestBody Map<String, Object> orderDetails) {
        // 存在漏洞的业务流程：将用户提供的callbackUrl直接传递给支付服务
        return paymentService.processPayment(callbackUrl, orderDetails);
    }
}

package com.example.ssrfdemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
