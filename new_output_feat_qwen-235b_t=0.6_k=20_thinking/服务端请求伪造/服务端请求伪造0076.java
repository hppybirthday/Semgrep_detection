package com.example.crawler.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

@Service
public class WebCrawlerService {
    private final RestTemplate restTemplate;
    private static final int MAX_REDIRECTS = 3;
    private static final String[] ALLOWED_SCHEMES = {"http", "https"};

    public WebCrawlerService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public CrawlResult crawlPage(String permalink, Map<String, String> headers) {
        try {
            URI targetUri = validateUrl(permalink);
            
            if (isInternalResource(targetUri)) {
                return new CrawlResult("Access denied to internal resources", 403);
            }

            // Add security headers
            Map<String, String> safeHeaders = new HashMap<>(headers);
            safeHeaders.putIfAbsent("User-Agent", "SecureCrawler/1.0");
            safeHeaders.put("X-Content-Type-Options", "nosniff");

            // Build final URI with tracking parameters
            URI finalUri = addTrackingParams(targetUri, safeHeaders);
            
            return executeRequest(finalUri, safeHeaders);
            
        } catch (Exception e) {
            return new CrawlResult("Crawling failed: " + e.getMessage(), 500);
        }
    }

    private URI validateUrl(String permalink) throws URISyntaxException {
        // Basic URL validation
        if (permalink == null || permalink.length() > 2048) {
            throw new IllegalArgumentException("Invalid URL length");
        }

        URI uri = new URI(permalink);
        String scheme = uri.getScheme().toLowerCase();
        
        // Allow only HTTP/HTTPS schemes
        boolean isValidScheme = false;
        for (String allowed : ALLOWED_SCHEMES) {
            if (allowed.equals(scheme)) {
                isValidScheme = true;
                break;
            }
        }
        
        if (!isValidScheme) {
            throw new IllegalArgumentException("Unsupported URL scheme");
        }
        
        return uri;
    }

    private boolean isInternalResource(URI uri) {
        // Simple check for internal resources
        String host = uri.getHost();
        if (host == null) return false;
        
        // Block localhost and private IP ranges
        return host.equals("localhost") || 
               host.startsWith("127.") ||
               host.startsWith("10.") ||
               host.startsWith("172.16.") ||
               host.startsWith("172.17.") ||
               host.startsWith("172.18.") ||
               host.startsWith("172.19.") ||
               host.startsWith("172.20.") ||
               host.startsWith("172.21.") ||
               host.startsWith("172.22.") ||
               host.startsWith("172.23.") ||
               host.startsWith("172.24.") ||
               host.startsWith("172.25.") ||
               host.startsWith("172.26.") ||
               host.startsWith("172.27.") ||
               host.startsWith("172.28.") ||
               host.startsWith("172.29.") ||
               host.startsWith("172.30.") ||
               host.startsWith("172.31.") ||
               host.startsWith("192.168.");
    }

    private URI addTrackingParams(URI uri, Map<String, String> headers) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUri(uri);
        
        // Add tracking parameters
        builder.queryParam("source", "crawler");
        builder.queryParam("timestamp", System.currentTimeMillis());
        
        return builder.build().encode().toUri();
    }

    private CrawlResult executeRequest(URI uri, Map<String, String> headers) {
        try {
            // Create request entity with headers
            org.springframework.http.HttpHeaders httpHeaders = new org.springframework.http.HttpHeaders();
            headers.forEach(httpHeaders::set);
            
            HttpEntity<String> requestEntity = new HttpEntity<>(httpHeaders);
            
            // Execute the request
            ResponseEntity<String> response = restTemplate.exchange(
                uri, HttpMethod.GET, requestEntity, String.class
            );
            
            return new CrawlResult(response.getBody(), response.getStatusCodeValue());
            
        } catch (Exception e) {
            return new CrawlResult("Request failed: " + e.getMessage(), 500);
        }
    }

    public static class CrawlResult {
        private final String content;
        private final int statusCode;

        public CrawlResult(String content, int statusCode) {
            this.content = content;
            this.statusCode = statusCode;
        }

        public String getContent() {
            return content;
        }

        public int getStatusCode() {
            return statusCode;
        }
    }
}