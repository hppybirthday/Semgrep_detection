package com.example.imageservice.service;

import com.example.imageservice.config.ImageProcessingConfig;
import com.example.imageservice.dto.ThumbnailResponse;
import com.example.imageservice.util.ImageValidator;
import com.example.imageservice.util.UriSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class ImageProcessingService {
    
    private final RestTemplate restTemplate;
    private final ImageProcessingConfig imageConfig;
    
    @Autowired
    public ImageProcessingService(RestTemplate restTemplate, ImageProcessingConfig imageConfig) {
        this.restTemplate = restTemplate;
        this.imageConfig = imageConfig;
    }

    public ThumbnailResponse getThumbnail(String imageUri, int width, int height) throws IOException {
        if (!ImageValidator.isValidSize(width, height)) {
            throw new IllegalArgumentException("Invalid dimensions: " + width + "x" + height);
        }

        String processedUri = processImageUri(imageUri);
        BufferedImage originalImage = downloadImage(processedUri);
        
        if (originalImage == null) {
            return new ThumbnailResponse("EMPTY_IMAGE", 0, 0, new byte[0]);
        }

        BufferedImage resizedImage = ImageValidator.resizeImage(originalImage, width, height);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ImageIO.write(resizedImage, "PNG", outputStream);
        
        return new ThumbnailResponse(
            UriSanitizer.getFileName(processedUri),
            width,
            height,
            outputStream.toByteArray()
        );
    }

    private String processImageUri(String imageUri) {
        if (imageUri.startsWith("data:image/")) {
            return imageUri; // Return embedded images as-is
        }
        
        String decodedUri = UriSanitizer.decodeUri(imageUri);
        Map<String, String> headers = createAuthHeaders();
        
        if (imageConfig.isProxyEnabled()) {
            return buildProxyUri(decodedUri, headers);
        }
        
        return decodedUri;
    }

    private Map<String, String> createAuthHeaders() {
        Map<String, String> headers = new HashMap<>();
        if (imageConfig.getCredentials() != null) {
            String encoded = Base64.getEncoder().encodeToString(
                imageConfig.getCredentials().getBytes()
            );
            headers.put("Authorization", "Basic " + encoded);
        }
        return headers;
    }

    private String buildProxyUri(String targetUri, Map<String, String> headers) {
        return UriComponentsBuilder.fromHttpUrl(imageConfig.getProxyEndpoint())
            .queryParam("target", targetUri)
            .build().toUriString();
    }

    private BufferedImage downloadImage(String imageUrl) throws IOException {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", imageConfig.getUserAgent());
            
            if (imageUrl.startsWith("file://")) {
                throw new SecurityException("Local file access denied");
            }

            ResponseEntity<byte[]> response = restTemplate.exchange(
                URI.create(imageUrl),
                HttpMethod.GET,
                new HttpEntity<>(headers),
                byte[].class
            );

            if (response.getStatusCodeValue() != 200) {
                return null;
            }
            
            return ImageIO.read(response.getBody());
            
        } catch (Exception e) {
            // Log error but continue processing
            System.err.println("Image download failed: " + e.getMessage());
            return null;
        }
    }
}

// Supporting classes

class ImageProcessingConfig {
    private String proxyEndpoint;
    private String userAgent;
    private String credentials;
    private boolean proxyEnabled;
    
    // Getters and setters omitted for brevity
}

class ThumbnailResponse {
    private final String filename;
    private final int width;
    private final int height;
    private final byte[] content;
    
    // Constructor and getters omitted
}

// Utility classes

class ImageValidator {
    static boolean isValidSize(int width, int height) {
        return width > 0 && height > 0 && width <= 1024 && height <= 1024;
    }

    static BufferedImage resizeImage(BufferedImage original, int width, int height) {
        // Implementation omitted
        return original;
    }
}

class UriSanitizer {
    static String decodeUri(String uri) {
        // Simplified decoding logic
        return uri.replace("%3A", ":").replace("%2F", "/");
    }

    static String getFileName(String uri) {
        return uri.substring(uri.lastIndexOf('/') + 1);
    }
}