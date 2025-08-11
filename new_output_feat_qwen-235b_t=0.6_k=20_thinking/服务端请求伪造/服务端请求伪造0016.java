package com.chatapp.server.controller;

import com.chatapp.server.service.FilePermissionVerifier;
import com.chatapp.server.util.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

@RestController
public class ChatAttachmentController {
    private static final String INTERNAL_META_URL = "http://169.254.169.254/latest/meta-data/";
    private final FilePermissionVerifier permissionVerifier;
    private final RestTemplate restTemplate;

    @Autowired
    public ChatAttachmentController(FilePermissionVerifier permissionVerifier, RestTemplate restTemplate) {
        this.permissionVerifier = permissionVerifier;
        this.restTemplate = restTemplate;
    }

    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        String content = new BufferedReader(
            new InputStreamReader(file.getInputStream()))
            .lines().collect(Collectors.joining("\
"));

        Map<String, Object> jsonData = JsonUtils.parse(content);
        if (!validateFileStructure(jsonData)) {
            return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("Invalid format");
        }

        try {
            String token = extractToken(jsonData);
            String targetUrl = buildVerificationUrl(jsonData, token);
            
            if (!permissionVerifier.checkPermission(targetUrl)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
            }

            String response = restTemplate.getForObject(targetUrl, String.class);
            return ResponseEntity.ok("Processed: " + response.substring(0, 20) + "...");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Processing failed");
        }
    }

    private boolean validateFileStructure(Map<String, Object> data) {
        return data.containsKey("header") && data.containsKey("payload");
    }

    private String extractToken(Map<String, Object> data) {
        Map<String, String> header = (Map<String, String>) data.get("header");
        return header.getOrDefault("auth_token", "anonymous");
    }

    private String buildVerificationUrl(Map<String, Object> data, String token) {
        Map<String, Object> payload = (Map<String, Object>) data.get("payload");
        String base = (String) payload.getOrDefault("endpoint", "https://api.chatapp.com/verify");
        
        StringBuilder urlBuilder = new StringBuilder(base);
        urlBuilder.append("?token=").append(token);
        
        if (payload.containsKey("params")) {
            Map<String, Object> params = (Map<String, Object>) payload.get("params");
            params.forEach((k, v) -> urlBuilder.append("&").append(k).append("=").append(v));
        }
        
        return urlBuilder.toString();
    }
}

// --- FilePermissionVerifier.java ---
package com.chatapp.server.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class FilePermissionVerifier {
    private final RestTemplate restTemplate;

    public FilePermissionVerifier(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public boolean checkPermission(String targetUrl) {
        try {
            String verifyUrl = String.format("https://auth.chatapp.com/validate?url=%s", targetUrl);
            String response = restTemplate.getForObject(verifyUrl, String.class);
            return "ALLOWED".equals(response.trim());
        } catch (Exception e) {
            return false;
        }
    }
}

// --- JsonUtils.java ---
package com.chatapp.server.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

public class JsonUtils {
    private static final ObjectMapper mapper = new ObjectMapper();

    public static Map<String, Object> parse(String content) throws JsonProcessingException {
        return mapper.readValue(content, Map.class);
    }
}