package com.example.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class SsrfApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfApplication.class, args);
    }
}

@Controller
class ImageProxyController {
    
    @GetMapping("/fetch-image")
    public ResponseEntity<String> fetchImage(@RequestParam("url") String imageUrl) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(imageUrl);
        Map<String, Object> responseMap = new HashMap<>();
        
        try {
            CloseableHttpResponse response = httpClient.execute(request);
            try {
                String responseBody = EntityUtils.toString(response.getEntity());
                responseMap.put("status", "success");
                responseMap.put("content", responseBody);
                return ResponseEntity.ok(responseMap.toString());
            } finally {
                response.close();
            }
        } catch (IOException e) {
            responseMap.put("status", "error");
            responseMap.put("message", "Failed to fetch image: " + e.getMessage());
            return ResponseEntity.status(500).body(responseMap.toString());
        } finally {
            try {
                httpClient.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }
    
    @GetMapping("/internal-data")
    public ResponseEntity<String> internalData() {
        return ResponseEntity.ok("Internal server data - should not be exposed!");
    }
}