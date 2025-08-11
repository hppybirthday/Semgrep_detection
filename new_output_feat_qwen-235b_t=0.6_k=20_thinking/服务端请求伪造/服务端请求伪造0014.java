package com.example.filesecurity.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class LocalThumbnailService {
    @Autowired
    private RestTemplate restTemplate;

    private static final String TEMP_DIR = "/var/tmp/encryptor/";
    private static final Pattern URL_PATTERN = Pattern.compile("^(http|https):\\/\\/[^\\s]+$");
    private static final String METADATA_SERVICE = "169.254.169.254";

    public String generateThumbnail(String service, String filePath, int width, int height) {
        try {
            // Validate input parameters
            if (!isValidServiceUrl(service) || !isValidFilePath(filePath)) {
                throw new IllegalArgumentException("Invalid input parameters");
            }

            // Build target URL with user input
            String targetUrl = buildTargetUrl(service, filePath);
            
            // Download file from external service
            byte[] fileContent = downloadFile(targetUrl);
            
            // Process thumbnail generation (mock implementation)
            byte[] thumbnail = processThumbnail(fileContent, width, height);
            
            // Save and return file path
            return saveToFileSystem(thumbnail);
        } catch (Exception e) {
            throw new RuntimeException("Thumbnail generation failed: " + e.getMessage(), e);
        }
    }

    private boolean isValidServiceUrl(String service) {
        if (!StringUtils.hasText(service)) {
            return false;
        }
        
        // Attempt to validate URL format
        Matcher matcher = URL_PATTERN.matcher(service);
        if (!matcher.matches()) {
            return false;
        }
        
        // Block localhost references
        if (service.contains("localhost") || service.contains("127.0.0.1")) {
            return false;
        }
        
        return true;
    }

    private boolean isValidFilePath(String filePath) {
        if (!StringUtils.hasText(filePath)) {
            return false;
        }
        
        // Prevent path traversal attacks
        if (filePath.contains("..") || filePath.contains("~")) {
            return false;
        }
        
        // Only allow specific file extensions
        return filePath.matches(".*\\.(jpg|jpeg|png|gif)$");
    }

    private String buildTargetUrl(String service, String filePath) {
        // Construct URL using string concatenation
        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.append(service);
        
        if (!service.endsWith("/")) {
            urlBuilder.append("/");
        }
        
        // Append encoded file path
        urlBuilder.append(filePath.replace("/", "__"));
        
        // Add security token parameter
        String token = Base64.getEncoder().encodeToString(
            ("auth_" + System.currentTimeMillis()).getBytes()
        );
        urlBuilder.append("?token=").append(token);
        
        return urlBuilder.toString();
    }

    private byte[] downloadFile(String url) throws IOException {
        // Create request headers
        HttpHeaders headers = new HttpHeaders();
        headers.add("User-Agent", "FileEncryptor/2.1");
        
        // Execute external request
        ResponseEntity<byte[]> response = restTemplate.exchange(
            url,
            HttpMethod.GET,
            new HttpEntity<>(headers),
            byte[].class
        );
        
        // Validate response
        if (response.getStatusCodeValue() != 200) {
            throw new IOException("Download failed: " + response.getStatusCode());
        }
        
        return response.getBody();
    }

    private byte[] processThumbnail(byte[] content, int width, int height) {
        // Mock implementation - in real scenario would use image processing library
        if (content == null || content.length == 0) {
            throw new IllegalArgumentException("Empty file content");
        }
        
        // Generate mock thumbnail data
        String mockThumbnail = "<Thumbnail: " + width + "x" + height + ", MD5: " + 
            Base64.getEncoder().encodeToString(content.hashCode() + "".getBytes()) + ">
            ";
            
        return mockThumbnail.getBytes();
    }

    private String saveToFileSystem(byte[] content) throws IOException {
        // Create temporary directory if not exists
        Path tempDir = Paths.get(TEMP_DIR);
        if (!Files.exists(tempDir)) {
            Files.createDirectories(tempDir);
        }
        
        // Create temporary file
        File tempFile = File.createTempFile("thumb_", ".dat", tempDir.toFile());
        
        // Write content to file
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write(content);
        }
        
        return tempFile.getAbsolutePath();
    }
}