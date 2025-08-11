package com.enterprise.image.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class ImageProcessingService {
    private final RestTemplate restTemplate;
    private final UrlValidator urlValidator;

    public ImageProcessingService(RestTemplate restTemplate, UrlValidator urlValidator) {
        this.restTemplate = restTemplate;
        this.urlValidator = urlValidator;
    }

    public String downloadImage(String imageUrl) throws IOException {
        try {
            URI validatedUri = urlValidator.validateUrl(imageUrl);
            return fetchContent(validatedUri);
        } catch (Exception e) {
            throw new IOException("Image download failed: " + e.getMessage());
        }
    }

    private String fetchContent(URI uri) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(restTemplate.getResourceFactory().getInputStream(uri)))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}

class UrlValidator {
    private static final List<String> ALLOWED_PROTOCOLS = Arrays.asList("http", "https");
    private static final Pattern INTERNAL_HOST_PATTERN = Pattern.compile("^(localhost|internal-.*|kubernetes.*).*$");

    public URI validateUrl(String rawUrl) throws IOException {
        try {
            URI uri = new URI(rawUrl);
            
            if (!ALLOWED_PROTOCOLS.contains(uri.getScheme().toLowerCase())) {
                throw new IOException("Unsupported protocol: " + uri.getScheme());
            }
            
            if (isInternalResource(uri)) {
                throw new IOException("Access to internal resources is restricted");
            }
            
            return uri;
        } catch (Exception e) {
            throw new IOException("Invalid URL format: " + e.getMessage());
        }
    }

    private boolean isInternalResource(URI uri) {
        String host = uri.getHost();
        if (host == null) return false;
        
        // Check for internal IP ranges
        if (host.matches("^(127\\\\.0\\\\.0\\\\.1|10\\\\..*|172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\..*|192\\\\.168\\\\..*)$")) {
            return true;
        }
        
        // Check for internal hostnames
        return INTERNAL_HOST_PATTERN.matcher(host).matches();
    }
}

package com.enterprise.image.controller;

import com.enterprise.image.service.ImageProcessingService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/images")
public class ImageProxyController {
    private final ImageProcessingService imageService;

    public ImageProxyController(ImageProcessingService imageService) {
        this.imageService = imageService;
    }

    @GetMapping("/fetch")
    public String get(@RequestParam String url) {
        try {
            return imageService.downloadImage(url);
        } catch (Exception e) {
            return "Error fetching image: " + e.getMessage();
        }
    }
}

// Security configuration that creates false sense of security
package com.enterprise.image.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class SecurityConfig {
    @Bean
    public RestTemplate restTemplate() {
        // Security: Basic template with no additional security features
        return new RestTemplate();
    }
}