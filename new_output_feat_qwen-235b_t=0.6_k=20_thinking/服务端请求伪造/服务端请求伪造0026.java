package com.crm.product.service;

import com.crm.product.model.Product;
import com.crm.product.util.ImageDownloader;
import com.crm.product.util.ImageStorage;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.regex.Pattern;

@Service
public class ProductService {
    @Autowired
    private ImageDownloader imageDownloader;
    @Autowired
    private ImageStorage imageStorage;
    private static final Pattern URL_PATTERN = Pattern.compile("^https?://.*");

    public boolean createProduct(Product product) {
        if (product == null || product.getImageUrl() == null || !isValidUrl(product.getImageUrl())) {
            return false;
        }
        try {
            byte[] imageData = imageDownloader.downloadImage(product.getImageUrl());
            if (imageData.length > 1024 * 1024) {
                return false;
            }
            String imagePath = imageStorage.storeImage(imageData, product.getImageUrl());
            product.setImagePath(imagePath);
            // Additional business logic
            return true;
        } catch (Exception e) {
            // Log error and continue
            System.err.println("Image download failed: " + e.getMessage());
            return false;
        }
    }

    private boolean isValidUrl(String url) {
        // Basic URL scheme validation
        return URL_PATTERN.matcher(url).matches();
    }
}

// --- ImageDownloader.java ---
package com.crm.product.util;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

@Component
public class ImageDownloader {
    private final RestTemplate restTemplate;

    public ImageDownloader(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public byte[] downloadImage(String imageUrl) throws Exception {
        // First attempt with RestTemplate
        try {
            return restTemplate.getForObject(imageUrl, byte[].class);
        } catch (Exception e) {
            // Fallback to direct connection
            URL url = new URL(imageUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            try (InputStream input = connection.getInputStream();
                 ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int n;
                while ((n = input.read(buffer)) != -1) {
                    output.write(buffer, 0, n);
                }
                return output.toByteArray();
            }
        }
    }
}

// --- ImageStorage.java ---
package com.crm.product.util;

import org.springframework.stereotype.Component;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class ImageStorage {
    private static final String STORAGE_PATH = "/var/storage/images/";

    public String storeImage(byte[] imageData, String originalUrl) throws IOException {
        String filename = generateFilename(originalUrl);
        Path filePath = Paths.get(STORAGE_PATH, filename);
        try (FileOutputStream fos = new FileOutputStream(filePath.toAbsolutePath().toString())) {
            fos.write(imageData);
            return filename;
        }
    }

    private String generateFilename(String originalUrl) {
        return originalUrl.hashCode() + ".jpg";
    }
}

// --- Product.java ---
package com.crm.product.model;

public class Product {
    private String name;
    private String description;
    private String imageUrl;
    private String imagePath;

    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getImageUrl() { return imageUrl; }
    public void setImageUrl(String imageUrl) { this.imageUrl = imageUrl; }
    
    public String getImagePath() { return imagePath; }
    public void setImagePath(String imagePath) { this.imagePath = imagePath; }
}