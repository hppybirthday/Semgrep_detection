package com.crm.example.controller;

import com.crm.example.service.ExternalServiceClient;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CustomerController {
    private final ExternalServiceClient externalService;

    public CustomerController(ExternalServiceClient externalService) {
        this.externalService = externalService;
    }

    @GetMapping("/profile")
    public String getCustomerProfile(@RequestParam String serviceUrl, @RequestParam String token) {
        return externalService.fetchData(serviceUrl, token);
    }
}

package com.crm.example.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

@Service
public class ExternalServiceClient {
    private final RestTemplate restTemplate;

    public ExternalServiceClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchData(String baseUrl, String accessToken) throws URISyntaxException {
        if (!UrlValidator.isValid(baseUrl)) {
            throw new IllegalArgumentException("Base URL validation failed");
        }
        
        URI targetUri = new URI(baseUrl);
        String finalUrl = String.format("%s?token=%s", targetUri.toString(), accessToken);
        
        return restTemplate.getForObject(finalUrl, String.class);
    }
}

class UrlValidator {
    static boolean isValid(String url) {
        try {
            if (url == null || url.isEmpty()) {
                return false;
            }
            
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            
            if (scheme == null) {
                return false;
            }
            
            return scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https");
        } catch (Exception e) {
            return false;
        }
    }
}