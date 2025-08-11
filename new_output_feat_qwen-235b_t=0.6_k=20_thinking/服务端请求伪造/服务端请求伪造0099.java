package com.example.crawler;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class ImageCrawlerService {
    private final ImageValidator imageValidator = new ImageValidator();
    private final StorageService storageService = new StorageService();

    public void executeCrawl(String requestUrl) {
        try {
            String validatedUrl = imageValidator.validateImageUrl(requestUrl);
            BufferedImage image = downloadImage(validatedUrl);
            String uploadUrl = storageService.uploadImage(image);
            System.out.println("Image uploaded to: " + uploadUrl);
        } catch (Exception e) {
            System.err.println("Crawl failed: " + e.getMessage());
        }
    }

    private BufferedImage downloadImage(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.connect();
        if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Failed to download image: HTTP error code " + connection.getResponseCode());
        }
        BufferedImage image = ImageIO.read(connection.getInputStream());
        connection.disconnect();
        return image;
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java ImageCrawlerApplication <image-url>");
            return;
        }
        ImageCrawlerService crawler = new ImageCrawlerService();
        crawler.executeCrawl(args[0]);
    }
}

class ImageValidator {
    public String validateImageUrl(String imageUrl) {
        if (imageUrl == null || imageUrl.isEmpty()) {
            throw new IllegalArgumentException("Image URL cannot be empty");
        }

        URL url;
        try {
            url = new URL(imageUrl);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid image URL format", e);
        }

        String protocol = url.getProtocol().toLowerCase();
        if (!protocol.equals("http") && !protocol.equals("https") && !protocol.equals("file")) {
            throw new IllegalArgumentException("Unsupported URL protocol: " + protocol);
        }

        String host = url.getHost();
        if (host.equalsIgnoreCase("127.0.0.1") || host.equalsIgnoreCase("localhost")) {
            System.out.println("Warning: Accessing loopback address is not recommended");
        }

        return imageUrl;
    }
}

class StorageService {
    public String uploadImage(BufferedImage image) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(image, "PNG", baos);
            String encodedImage = Base64.getEncoder().encodeToString(baos.toByteArray());
            return "https://storage.example.com/images/" + encodedImage.substring(0, 10);
        } catch (Exception e) {
            throw new RuntimeException("Image upload failed", e);
        }
    }
}