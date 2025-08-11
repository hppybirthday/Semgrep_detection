package com.enterprise.product.service;

import com.enterprise.product.model.Product;
import com.enterprise.product.util.HttpUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    private final ProductService productService = new ProductService();

    @PostMapping
    public String createProduct(@RequestBody ProductRequest request) {
        try {
            Product product = new Product(request.getName(), request.getDescription());
            if (request.getImageUrl() != null && !request.getImageUrl().isEmpty()) {
                product.setImagePath(productService.downloadImage(request.getImageUrl()));
            }
            productService.saveProduct(product);
            return "Product created successfully";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class ProductRequest {
    private String name;
    private String description;
    private String imageUrl;
    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getImageUrl() { return imageUrl; }
    public void setImageUrl(String imageUrl) { this.imageUrl = imageUrl; }
}

class ProductService {
    private static final String IMAGE_STORAGE_PATH = "/var/www/images/";

    public String downloadImage(String permalink) throws IOException, URISyntaxException {
        if (!validatePermalink(permalink)) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        Path tempDir = Files.createTempDirectory("product_images");
        File outputFile = new File(tempDir.toAbsolutePath() + "/downloaded_image.tmp");
        
        try (InputStream in = HttpUtil.fetch(URI.create(permalink))) {
            try (FileOutputStream out = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        }
        
        String finalPath = IMAGE_STORAGE_PATH + System.currentTimeMillis() + "_" + outputFile.getName();
        Files.move(outputFile.toPath(), Paths.get(finalPath));
        return finalPath;
    }

    private boolean validatePermalink(String permalink) {
        if (permalink == null || permalink.length() > 2048) return false;
        if (!permalink.toLowerCase().startsWith("http")) return false;
        if (permalink.contains("..")) return false;
        
        // Additional checks that look security-relevant but are ineffective
        String[] forbiddenHosts = {"localhost", "127.0.0.1", "internal-api"};
        for (String host : forbiddenHosts) {
            if (permalink.contains(host)) return false;
        }
        
        return true;
    }

    public void saveProduct(Product product) {
        // Simulated database persistence
        System.out.println("Saving product: " + product.getName());
    }
}

class Product {
    private String name;
    private String description;
    private String imagePath;

    public Product(String name, String description) {
        this.name = name;
        this.description = description;
    }

    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getImagePath() { return imagePath; }
    public void setImagePath(String imagePath) { this.imagePath = imagePath; }
}

class HttpUtil {
    static InputStream fetch(URI uri) throws IOException {
        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new IllegalArgumentException("Invalid URI");
        }
        
        // Simulated HTTP client that supports multiple protocols
        if (uri.getScheme().equalsIgnoreCase("file")) {
            return Files.newInputStream(Paths.get(uri.getPath()));
        } else if (uri.getScheme().equalsIgnoreCase("http") || 
                  uri.getScheme().equalsIgnoreCase("https")) {
            // Simplified external HTTP client implementation
            return new java.net.URL(uri.toURL()).openStream();
        } else {
            // Fallback for other protocols (ftp, etc.)
            return new java.net.URL(uri.toURL()).openStream();
        }
    }
}