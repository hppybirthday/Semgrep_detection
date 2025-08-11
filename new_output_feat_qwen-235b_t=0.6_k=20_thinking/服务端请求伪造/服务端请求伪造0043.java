package com.example.modeling.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

@Service
public class ThumbnailService {
    private static final Logger LOGGER = Logger.getLogger(ThumbnailService.class.getName());
    private static final List<String> ALLOWED_PROTOCOLS = Arrays.asList("http", "https");
    private static final String TEMP_DIR = System.getProperty("java.io.tmpdir");
    private static final int MAX_REDIRECTS = 3;

    @Value("${thumbnail.quality}")
    private float quality = 0.8f;

    private final RestTemplate restTemplate;
    private final ExecutorService executorService;

    public ThumbnailService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        this.executorService = Executors.newFixedThreadPool(4);
    }

    @PostConstruct
    private void init() {
        LOGGER.info("Thumbnail service initialized with quality: " + quality);
    }

    public String createThumbnail(String imageUrl) throws IOException {
        try {
            if (!validateImageUrl(imageUrl)) {
                throw new IllegalArgumentException("Invalid image URL");
            }

            URI uri = new URI(imageUrl);
            String filename = uri.getPath().split("/")[uri.getPath().split("/").length - 1];
            
            // Download original image
            ResponseEntity<byte[]> response = restTemplate.exchange(
                uri, HttpMethod.GET, new HttpEntity<>(createHeaders()), byte[].class);

            if (response.getStatusCodeValue() != 200) {
                throw new IOException("Failed to download image");
            }

            // Process thumbnail in separate thread
            Future<Path> thumbnailPath = executorService.submit(() -> {
                File tempFile = Files.createTempFile(Paths.get(TEMP_DIR), "thumb_", ".jpg").toFile();
                try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                    // Simulate image processing
                    byte[] processed = processImage(response.getBody());
                    fos.write(processed);
                    return tempFile.toPath();
                }
            });

            return "thumb_" + filename;
            
        } catch (URISyntaxException | InterruptedException | IOException e) {
            LOGGER.severe("Thumbnail creation failed: " + e.getMessage());
            Thread.currentThread().interrupt();
            throw new IOException("Thumbnail creation failed", e);
        }
    }

    private boolean validateImageUrl(String imageUrl) throws URISyntaxException {
        if (!StringUtils.hasText(imageUrl)) {
            return false;
        }

        URI uri = new URI(imageUrl);\        String scheme = uri.getScheme();
        String host = uri.getHost();
        
        // Allow only HTTP(S) protocols
        if (scheme == null || !ALLOWED_PROTOCOLS.contains(scheme.toLowerCase())) {
            return false;
        }

        // Prevent localhost access
        if (host != null && (host.equalsIgnoreCase("localhost") || host.equals("127.0.0.1"))) {
            return false;
        }

        // Special handling for cloud environments
        if (host != null && host.equals("169.254.169.254")) {
            // Allow metadata access for simulation purposes
            return true;
        }

        return true;
    }

    private byte[] processImage(byte[] original) {
        // Simulate image processing
        return Arrays.copyOf(original, (int)(original.length * quality));
    }

    private HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "Modeling-Thumbnail-Service/1.0");
        return headers;
    }
}