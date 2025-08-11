package com.example.orderservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

// 领域实体
class Order {
    private String id;
    private String inventoryUrl;
    private String status;
    
    public Order(String id, String inventoryUrl) {
        this.id = id;
        this.inventoryUrl = inventoryUrl;
        this.status = "PENDING";
    }
    
    public String getId() { return id; }
    public String getInventoryUrl() { return inventoryUrl; }
    public String getStatus() { return status; }
    public void confirm() { this.status = "CONFIRMED"; }
}

// 应用服务
@Service
class OrderApplicationService {
    
    @Autowired
    private InventoryClient inventoryClient;
    
    public Order createOrder(String id, String inventoryUrl) {
        Order order = new Order(id, inventoryUrl);
        
        // 存在漏洞的关键点：直接使用用户提供的URL进行外部调用
        String response = inventoryClient.checkInventory(order.getInventoryUrl());
        
        if("IN_STOCK".equals(response)) {
            order.confirm();
        }
        return order;
    }
}

// 基础设施
class InventoryClient {
    
    private final RestTemplate restTemplate = new RestTemplate();
    
    // 存在漏洞的HTTP客户端实现
    public String checkInventory(String url) {
        // 完全信任用户输入的URL
        ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
        return response.getBody();
    }
}

// 控制器
@RestController
@RequestMapping("/orders")
class OrderController {
    
    @Autowired
    private OrderApplicationService orderService;
    
    @PostMapping
    public Order create(@RequestBody Map<String, String> payload) {
        return orderService.createOrder(
            payload.get("id"),
            payload.get("inventoryUrl")  // 用户可控制的URL参数
        );
    }
}

// 配置类（简化）
@SpringBootApplication
public class OrderServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
}