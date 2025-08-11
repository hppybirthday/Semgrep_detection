package com.example.vulnerablemicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

@SpringBootApplication
@RestController
@RequestMapping("/orders")
public class OrderProcessingService {

    public static void main(String[] args) {
        SpringApplication.run(OrderProcessingService.class, args);
    }

    @PostMapping("/process")
    public String processOrder(@RequestParam("data") String base64Data) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bais);
            Order order = (Order) ois.readObject();
            ois.close();
            
            // Business logic that inadvertently triggers gadget chain
            OrderValidator.validateOrder(order);
            
            return "Order processed successfully";
        } catch (Exception e) {
            return "Error processing order: " + e.getMessage();
        }
    }
}

class Order implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private String orderId;
    private String customerName;
    private transient OrderDetails details; // Non-serializable but ignored in our case

    // Getters and setters
    public String getOrderId() { return orderId; }
    public void setOrderId(String orderId) { this.orderId = orderId; }
    
    public String getCustomerName() { return customerName; }
    public void setCustomerName(String customerName) { this.customerName = customerName; }
}

class OrderDetails {
    // Complex business data structure that could be exploited
    private String sensitiveData;
}

class OrderValidator {
    public static void validateOrder(Order order) {
        // Vulnerable code pattern that triggers gadget chain
        if (order.getCustomerName() != null) {
            System.out.println("Validating order for: " + order.getCustomerName());
        }
        
        // Simulated business rule that inadvertently processes malicious data
        String validationRule = System.getenv("ORDER_VALIDATION_RULE");
        if (validationRule != null && validationRule.equals(order.getOrderId())) {
            throw new SecurityException("Order validation failed");
        }
    }
}