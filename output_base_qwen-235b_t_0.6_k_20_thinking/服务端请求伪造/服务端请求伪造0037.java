package com.example.demo.product;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @PostMapping
    public Map<String, String> createProduct(@RequestBody Product product) {
        try {
            String imagePath = productService.processProductImage(product.getImageUrl());
            Map<String, String> response = new HashMap<>();
            response.put("status", "success");
            response.put("imagePath", imagePath);
            return response;
        } catch (Exception e) {
            return Map.of("status", "error", "message", e.getMessage());
        }
    }
}

@Service
class ProductService {
    public String processProductImage(String imageUrl) throws Exception {
        String localPath = "/tmp/product_images/" + UUID.randomUUID() + ".jpg";
        
        // 漏洞点：直接使用用户输入的URL发起外部请求
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(imageUrl))
            .build();
        
        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        
        if (response.statusCode() == 200) {
            Files.write(Paths.get(localPath), response.body());
            return localPath;
        }
        throw new RuntimeException("Image download failed");
    }
}

record Product(String name, String description, String imageUrl) {}
