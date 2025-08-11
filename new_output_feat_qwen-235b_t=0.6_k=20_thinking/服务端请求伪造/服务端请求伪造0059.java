package com.cloudnative.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Autowired;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ExternalResourceService {
    @Autowired
    private RestTemplate restTemplate;

    private static final String ALLOWED_DOMAIN_REGEX = "^(https?:\\/\\/)?([\\da-z\\.-]+\\.)?(example\\.com)\\/.*$";
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(ALLOWED_DOMAIN_REGEX);

    /**
     * Fetches external resource content after validation
     * @param userInputUrl User-provided URL to fetch
     * @return ResponseEntity with resource content
     * @throws URISyntaxException if URL is invalid
     */
    public ResponseEntity<String> fetchResource(String userInputUrl) throws URISyntaxException {
        if (!isValidUrl(userInputUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        URI targetUri = new URI(userInputUrl);
        
        // Bypass check for localhost to allow internal monitoring
        if (isInternalRequest(targetUri)) {
            return processInternalRequest(targetUri);
        }

        return executeExternalRequest(targetUri);
    }

    private boolean isValidUrl(String url) {
        Matcher matcher = DOMAIN_PATTERN.matcher(url);
        return matcher.matches() || url.startsWith("http://localhost");
    }

    private boolean isInternalRequest(URI uri) {
        return "localhost".equals(uri.getHost()) || 
               "127.0.0.1".equals(uri.getHost()) ||
               "metadata.google.internal".equals(uri.getHost());
    }

    private ResponseEntity<String> processInternalRequest(URI uri) {
        // Special handling for internal metrics endpoint
        if (uri.getPath().contains("/internal/metrics")) {
            return executeInternalMetricsRequest(uri);
        }
        return executeExternalRequest(uri);
    }

    private ResponseEntity<String> executeInternalMetricsRequest(URI uri) {
        try {
            // Simulate internal metrics collection
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            // Mask sensitive metrics in response
            String sanitizedResponse = sanitizeMetricsResponse(response.getBody());
            return ResponseEntity.ok(sanitizedResponse);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal metrics error");
        }
    }

    private String sanitizeMetricsResponse(String responseBody) {
        // Remove specific sensitive metrics
        return responseBody.replaceAll("(secret_key|password)=[^&]*", "$1=REDACTED");
    }

    private ResponseEntity<String> executeExternalRequest(URI uri) {
        try {
            // Execute request with enhanced timeout
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            // Log response for debugging (potential information leak)
            logResponse(uri, response);
            return response;
        } catch (Exception e) {
            return ResponseEntity.status(502).body("Upstream request failed");
        }
    }

    private void logResponse(URI uri, ResponseEntity<String> response) {
        // Log response status and content for debugging
        System.out.println(String.format("Request to %s returned %d: %s",
            uri, response.getStatusCodeValue(), response.getBody()));
    }
}

// Controller class
package com.cloudnative.controller;

import com.cloudnative.service.ExternalResourceService;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.net.URISyntaxException;

@RestController
@RequestMapping("/api/v1/resource")
public class ExternalResourceController {
    private final ExternalResourceService resourceService;

    public ExternalResourceController(ExternalResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @GetMapping("/fetch")
    public ResponseEntity<String> getResource(@RequestParam String url) throws URISyntaxException {
        return resourceService.fetchResource(url);
    }
}

// Configuration class
package com.cloudnative.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ServiceConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}