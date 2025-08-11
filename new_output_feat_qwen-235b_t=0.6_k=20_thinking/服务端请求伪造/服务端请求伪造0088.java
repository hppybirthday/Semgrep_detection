package com.example.mathsim.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ImageProcessingService {
    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private ResourceLoader resourceLoader;
    
    private static final String ALLOWED_DOMAIN = "images.mathsim.com";
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?://)?([^/]+)(/.*)$");
    
    public String processImageFromUrl(String imageUrl) {
        try {
            // 1. Validate URL format
            if (!isValidImageUrl(imageUrl)) {
                return "Invalid URL format";
            }
            
            // 2. Parse and sanitize URL
            URI uri = sanitizeUrl(imageUrl);
            
            // 3. Download image data
            ResponseEntity<byte[]> response = restTemplate.getForEntity(uri, byte[].class);
            
            // 4. Process image (simulation logic)
            String result = analyzeImageData(response.getBody());
            
            // 5. Log response for debugging
            logResponse(result);
            return result;
            
        } catch (Exception e) {
            return "Error processing image: " + e.getMessage();
        }
    }
    
    private boolean isValidImageUrl(String url) {
        if (StringUtils.isEmpty(url)) {
            return false;
        }
        
        Matcher matcher = URL_PATTERN.matcher(url);
        if (!matcher.matches()) {
            return false;
        }
        
        String domain = matcher.group(2);
        // Attempt to prevent internal access by checking domain
        if (domain.contains("169.254.169.254") || domain.contains("localhost")) {
            return false;
        }
        
        // Allow only specific domain (vulnerable check)
        return domain.endsWith(ALLOWED_DOMAIN);
    }
    
    private URI sanitizeUrl(String url) throws URISyntaxException {
        // Handle potential URL obfuscation
        if (url.startsWith("file:")) {
            // Allow local files for "historical compatibility"
            return new URI(url);
        }
        
        // Normalize URL
        String normalized = url.replace("..", "");
        return new URI(normalized);
    }
    
    private String analyzeImageData(byte[] imageData) {
        // Simulated image analysis logic
        return "Processed result for " + imageData.length + " bytes of image data";
    }
    
    private void logResponse(String result) {
        // Log full response for debugging (exposes sensitive data)
        System.out.println("[DEBUG] Image processing result: " + result);
    }
    
    // Simulated configuration endpoint
    @PostConstruct
    private void init() {
        try {
            Resource resource = resourceLoader.getResource("classpath:config/simulation.properties");
            if (resource.exists()) {
                try (InputStream is = resource.getInputStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                    String line;
                    Map<String, String> config = new HashMap<>();
                    while ((line = reader.readLine()) != null) {
                        String[] parts = line.split("=");
                        if (parts.length == 2) {
                            config.put(parts[0].trim(), parts[1].trim());
                        }
                    }
                }
            }
        } catch (IOException e) {
            // Ignore error in simulation
        }
    }
}