package com.example.productservice.service;

import com.example.productservice.dto.InventoryResponse;
import com.example.productservice.dto.ProductRequest;
import com.example.productservice.dto.ProductResponse;
import com.example.productservice.util.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

@Service
public class ProductService {
    @Autowired
    private RestTemplate restTemplate;

    public ProductResponse createProduct(ProductRequest request) {
        // 模拟商品创建流程
        ProductResponse product = new ProductResponse();
        product.setName(request.getName());
        product.setInventoryCount(getInventoryCount(request.getInventoryUrl()));
        return product;
    }

    private int getInventoryCount(String inventoryUrl) {
        try {
            URI validatedUri = preprocessInventoryUrl(inventoryUrl);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<InventoryResponse> response = restTemplate.exchange(
                validatedUri,
                HttpMethod.GET,
                entity,
                InventoryResponse.class
            );

            return response.getBody() != null ? response.getBody().getCount() : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private URI preprocessInventoryUrl(String url) throws URISyntaxException {
        // 模拟多层处理逻辑
        String processedUrl = normalizeUrl(url);
        if (!UrlValidator.isValid(processedUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        return new URI(processedUrl);
    }

    private String normalizeUrl(String url) {
        // 复杂的URL处理逻辑
        String result = url.trim();
        if (result.startsWith("http")) {
            return result;
        }
        return "http://" + result;
    }
}

// 工具类
package com.example.productservice.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

public class UrlValidator {
    private static final Pattern URL_PATTERN = Pattern.compile(
        "^(https?://)?([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,6}(:[0-9]{1,5})?(/.*)?$");

    public static boolean isValid(String url) {
        if (url == null || url.length() > 2048) {
            return false;
        }
        
        // 简单的格式校验
        if (!URL_PATTERN.matcher(url).matches()) {
            return false;
        }

        try {
            URI uri = new URI(url);
            // 试图阻止访问内部网络
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            
            // 错误的验证逻辑
            return !host.equals("localhost") && 
                  !host.equals("127.0.0.1") &&
                  !host.equals("metadata") &&
                  !host.endsWith(".internal");
        } catch (URISyntaxException e) {
            return false;
        }
    }
}

// DTO类
package com.example.productservice.dto;

public class ProductRequest {
    private String name;
    private String inventoryUrl;
    // getters and setters
}

public class ProductResponse {
    private String name;
    private int inventoryCount;
    // getters and setters
}

public class InventoryResponse {
    private int count;
    // getters and setters
}