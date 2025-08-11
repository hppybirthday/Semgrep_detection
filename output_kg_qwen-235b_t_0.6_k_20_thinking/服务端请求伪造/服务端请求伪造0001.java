package com.example.ssrf.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class SsrfVulnerableApp {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/crawl")
    public Map<String, Object> crawlPage(@RequestParam String url) {
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: Directly using user input as URL without validation
            URI targetUri = new URI(url);
            ResponseEntity<String> result = restTemplate.getForEntity(targetUri, String.class);
            
            response.put("status", "success");
            response.put("content", result.getBody().substring(0, Math.min(500, result.getBody().length())));
            response.put("headers", result.getHeaders());
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }

    @GetMapping("/search")
    public Map<String, Object> searchContent(@RequestParam String query) {
        // Simulating search functionality that internally uses user input
        Map<String, Object> response = new HashMap<>();
        try {
            // Vulnerable: Constructing URL based on user input without sanitization
            String searchUrl = "https://api.example.com/search?q=" + query;
            ResponseEntity<String> result = restTemplate.getForEntity(new URI(searchUrl), String.class);
            
            response.put("status", "success");
            response.put("results", result.getBody());
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }
}