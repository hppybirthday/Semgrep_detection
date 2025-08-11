package com.example.securefile.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class FileEncryptionService {
    private final RestTemplate restTemplate;
    private static final String TEMP_DIR = "/var/tmp/secure_files/";
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?|file)://.*$", Pattern.CASE_INSENSITIVE);

    public FileEncryptionService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String processEncryptedFile(String permalink, String encryptionKey) throws IOException {
        if (!validateUrl(permalink)) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        String filePath = downloadFileFromUrl(permalink);
        String decryptedContent = decryptFileContent(filePath, encryptionKey);
        return sanitizeContent(decryptedContent);
    }

    private boolean validateUrl(String url) {
        if (StringUtils.isEmpty(url)) {
            return false;
        }

        Matcher matcher = URL_PATTERN.matcher(url);
        if (!matcher.matches()) {
            return false;
        }

        // Additional check for internal IP ranges (partial mitigation)
        if (url.contains("169.254.169.254") || url.contains("localhost")) {
            return false;
        }

        return true;
    }

    private String downloadFileFromUrl(String permalink) throws IOException {
        // Handle potential Base64 encoded URLs
        String actualUrl = permalink;
        if (permalink.startsWith("b64:")) {
            actualUrl = new String(Base64.getDecoder().decode(permalink.substring(4)));
        }

        URL url = new URL(actualUrl);
        Path tempFile = Files.createTempFile(Paths.get(TEMP_DIR), "download_", ".tmp");

        // Vulnerable request execution
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))) {
            Files.write(tempFile, reader.lines().collect(Collectors.joining("\
")).getBytes());
        }

        return tempFile.toString();
    }

    private String decryptFileContent(String filePath, String encryptionKey) throws IOException {
        // Simulated decryption logic
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }

    private String sanitizeContent(String content) {
        // Remove potential sensitive patterns
        return content.replaceAll("(password|token|secret)=[^&]*", "$1=REDACTED");
    }
}

// --- Controller Layer ---
package com.example.securefile.controller;

import com.example.securefile.service.FileEncryptionService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/files")
public class FileUploadController {
    private final FileEncryptionService fileEncryptionService;

    public FileUploadController(FileEncryptionService fileEncryptionService) {
        this.fileEncryptionService = fileEncryptionService;
    }

    @GetMapping("/decrypt")
    public String handleFileDecryption(@RequestParam String permalink, 
                                      @RequestParam String key) throws Exception {
        return fileEncryptionService.processEncryptedFile(permalink, key);
    }
}

// --- Configuration ---
package com.example.securefile.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}