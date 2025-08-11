package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

@SpringBootApplication
public class OrderServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
}

@RestController
class OrderController {
    @PostMapping(path = "/process-order", consumes = MediaType.APPLICATION_JSON_VALUE)
    public String processOrder(byte[] orderData) {
        try {
            // 不安全的反序列化操作
            ByteArrayInputStream bis = new ByteArrayInputStream(orderData);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Order order = (Order) ois.readObject();
            ois.close();
            
            // 模拟业务处理
            return "Processing order: " + order.getId();
        } catch (Exception e) {
            return "Error processing order: " + e.getMessage();
        }
    }
}

class Order implements Serializable {
    private static final long serialVersionUID = 1L;
    private String id;
    private String customerName;
    private transient Runtime runtime = Runtime.getRuntime(); // 危险的瞬态字段
    
    public Order() {
        // 默认构造函数
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCustomerName() {
        return customerName;
    }

    public void setCustomerName(String customerName) {
        this.customerName = customerName;
    }
}