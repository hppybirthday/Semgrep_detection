package com.example.productservice.controller;

import com.example.productservice.service.ImageDownloader;
import com.example.productservice.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.Map;

@RestController
@RequestMapping("/products")
public class ProductController {
    @Autowired
    private ProductService productService;

    @PostMapping
    public String createProduct(@RequestBody Map<String, Object> productData) {
        String imageUrl = (String) productData.get("image_url");
        String result = productService.processImageDownload(imageUrl);
        return String.format("{\"status\":\"success\",\"image_data\":\"%s\"}", result);
    }
}

package com.example.productservice.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URL;

@Service
public class ProductService {
    @Autowired
    private ImageDownloader imageDownloader;

    public String processImageDownload(String inputUrl) {
        try {
            URL parsedUrl = parseImageUrl(inputUrl);
            return imageDownloader.downloadImage(parsedUrl);
        } catch (Exception e) {
            return "ERROR: Invalid image URL format";
        }
    }

    private URL parseImageUrl(String inputUrl) throws Exception {
        // 仅验证基础协议格式
        if (!inputUrl.startsWith("http://") && !inputUrl.startsWith("https://")) {
            throw new IllegalArgumentException("Invalid URL scheme");
        }
        return new URL(inputUrl);
    }
}

package com.example.productservice.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URL;

@Service
public class ImageDownloader {
    private final RestTemplate restTemplate;

    public ImageDownloader() {
        this.restTemplate = new RestTemplate();
    }

    public String downloadImage(URL imageUrl) {
        // 直接使用用户提供的URL发起请求
        return restTemplate.getForObject(imageUrl, String.class);
    }
}