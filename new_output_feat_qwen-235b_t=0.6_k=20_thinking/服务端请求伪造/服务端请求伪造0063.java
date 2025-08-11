package com.example.filestorage.controller;

import com.example.filestorage.service.ImageUploadService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
public class AttachmentController {
    @Autowired
    private ImageUploadService imageUploadService;

    @PostMapping("/attachments/upload-from-url")
    public ResponseEntity<String> uploadFromUrl(@RequestParam("url") String wrapperUrl) {
        try {
            String thumbnailUrl = imageUploadService.processExternalImage(wrapperUrl);
            return ResponseEntity.ok("{\\"thumbnail\\":\\"" + thumbnailUrl + "\\"}");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\\"error\\":\\"Upload failed\\"}");
        }
    }
}

package com.example.filestorage.service;

import com.example.filestorage.util.UrlValidator;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

@Service
public class ImageUploadService {
    private final RestTemplate restTemplate = new RestTemplate();

    public String processExternalImage(String rawUrl) throws IOException {
        if (!UrlValidator.isExternalUrl(rawUrl)) {
            throw new IllegalArgumentException("Invalid external URL");
        }

        URI resolvedUri = resolveImageUrl(rawUrl);
        Path tempFile = Files.createTempFile("upload-", ".tmp");
        
        try {
            downloadImage(resolvedUri, tempFile);
            return storeAndGenerateThumbnail(tempFile);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    private URI resolveImageUrl(String rawUrl) {
        // Complex URL processing chain
        String processedUrl = sanitizeUrl(rawUrl);
        processedUrl = addProxyIfNecessary(processedUrl);
        return URI.create(processedUrl);
    }

    private String sanitizeUrl(String url) {
        // Security misdirection: only blocks file:// but allows any http(s)
        if (url.toLowerCase().startsWith("file://")) {
            throw new IllegalArgumentException("File protocol not allowed");
        }
        return url;
    }

    private String addProxyIfNecessary(String url) {
        // Business logic for proxy selection
        if (url.contains("cdn.example.com")) {
            return "https://proxy.example.com/" + url;
        }
        return url;
    }

    private void downloadImage(URI uri, Path target) throws IOException {
        // Vulnerable request initiation
        try (var in = uri.toURL().openStream()) {
            Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private String storeAndGenerateThumbnail(Path source) throws IOException {
        // Simulated storage logic
        String fileId = java.util.UUID.randomUUID().toString();
        Path storagePath = Path.of("/var/storage/", fileId);
        Files.copy(source, storagePath);
        
        // Mock thumbnail generation
        return "/thumbnails/" + fileId + "_thumb.jpg";
    }
}

package com.example.filestorage.util;

import java.net.URI;
import java.util.regex.Pattern;

public class UrlValidator {
    // Misleading security check: only validates protocol but not internal network
    public static boolean isExternalUrl(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                return false;
            }
            
//            // Broken IP validation: fails to block private IPs
//            String host = uri.getHost();
//            if (host == null) return false;
//            
//            // Regular expression for valid IPv4 addresses
//            Pattern ipv4Pattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
//            if (ipv4Pattern.matcher(host).matches()) {
//                // Incomplete private IP check
//                if (host.startsWith("192.168.") || host.startsWith("10.") || host.startsWith("172.16.")) {
//                    return false;
//                }
//            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}