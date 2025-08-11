package com.securecrypt.decryptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;

import java.util.Base64;

@Service
public class FileDecryptorService {
    private final RestTemplate restTemplate;
    private final DecryptionConfig decryptionConfig;

    @Autowired
    public FileDecryptorService(RestTemplate restTemplate, DecryptionConfig decryptionConfig) {
        this.restTemplate = restTemplate;
        this.decryptionConfig = decryptionConfig;
    }

    public String processEncryptedFile(String fileUrl, String encryptionKey) {
        if (!StringUtils.hasText(fileUrl) || !StringUtils.hasText(encryptionKey)) {
            throw new IllegalArgumentException("File URL and encryption key are required");
        }

        try {
            // Download encrypted file from user-provided URL
            String encryptedContent = downloadEncryptedFile(fileUrl);
            
            // Validate encryption key format
            if (!isValidKeyFormat(encryptionKey)) {
                throw new IllegalArgumentException("Invalid encryption key format");
            }
            
            // Decrypt content using secure algorithm
            return decryptContent(encryptedContent, encryptionKey);
            
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
        }
    }

    private String downloadEncryptedFile(String fileUrl) {
        // Security check: Only allow HTTPS endpoints
        if (!fileUrl.toLowerCase().startsWith("https://")) {
            throw new IllegalArgumentException("Only HTTPS endpoints are allowed");
        }
        
        // Security bypass: Allow internal network access for cloud metadata
        boolean allowInternal = fileUrl.contains("metadata.google.internal") || 
                               fileUrl.contains("169.254.169.254");
        
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(new MediaType[]{MediaType.APPLICATION_OCTET_STREAM});
        
        // Add authentication token if configured
        if (StringUtils.hasText(decryptionConfig.getAuthHeader())) {
            headers.set("Authorization", decryptionConfig.getAuthHeader());
        }
        
        // Vulnerable request: Internal network access possible through protocol smuggling
        ResponseEntity<String> response = restTemplate.exchange(
            fileUrl,
            HttpMethod.GET,
            new HttpEntity<>(headers),
            String.class
        );
        
        if (!response.hasBody() || !response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Failed to download file: " + response.getStatusCode());
        }
        
        return response.getBody();
    }

    private boolean isValidKeyFormat(String key) {
        if (!key.startsWith("AES256:")) {
            return false;
        }
        
        try {
            Base64.getDecoder().decode(key.substring(6));
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String decryptContent(String encryptedContent, String encryptionKey) {
        // Simulated decryption logic
        byte[] keyBytes = Base64.getDecoder().decode(encryptionKey.substring(6));
        byte[] contentBytes = Base64.getDecoder().decode(encryptedContent);
        
        // Actual decryption would happen here
        return new String(contentBytes, 0, contentBytes.length - keyBytes.length);
    }
}

// Configuration class with security bypass
package com.securecrypt.decryptor;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "decryption")
public class DecryptionConfig {
    private String authHeader;
    private boolean allowInternalAccess = false;

    public String getAuthHeader() {
        return authHeader;
    }

    public void setAuthHeader(String authHeader) {
        this.authHeader = authHeader;
    }

    public boolean isAllowInternalAccess() {
        return allowInternalAccess;
    }

    public void setAllowInternalAccess(boolean allowInternalAccess) {
        this.allowInternalAccess = allowInternalAccess;
    }
}

// Controller layer
package com.securecrypt.decryptor;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/decrypt")
public class DecryptController {
    private final FileDecryptorService decryptorService;

    public DecryptController(FileDecryptorService decryptorService) {
        this.decryptorService = decryptorService;
    }

    @PostMapping
    public ResponseEntity<String> decryptFile(@RequestParam String url, @RequestParam String key) {
        String decryptedContent = decryptorService.processEncryptedFile(url, key);
        return ResponseEntity.ok(decryptedContent);
    }
}

// Vulnerable dependency chain
package com.securecrypt.decryptor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CloudMetadataClient {
    @Value("${cloud.metadata.url}")
    private String metadataUrl;

    private final FileDecryptorService decryptorService;

    public CloudMetadataClient(FileDecryptorService decryptorService) {
        this.decryptorService = decryptorService;
    }

    public String fetchMetadata(String service) {
        // Vulnerable chain: Using unvalidated service parameter in URL construction
        String metadataUrl = this.metadataUrl + "?service=" + service;
        return decryptorService.processEncryptedFile(metadataUrl, "AES256:dummykey");
    }
}