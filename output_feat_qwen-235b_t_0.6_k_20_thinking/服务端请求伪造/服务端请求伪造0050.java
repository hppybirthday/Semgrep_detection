package com.chatapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/thumbnail")
public class ThumbnailController {
    @Autowired
    private ThumbnailService thumbnailService;

    @GetMapping("/generate")
    public String generateThumbnail(@RequestParam String imageUri) {
        try {
            return thumbnailService.processImage(imageUri);
        } catch (IOException e) {
            return "Error processing image: " + e.getMessage();
        }
    }
}

class ThumbnailService {
    public String processImage(String imageUri) throws IOException {
        return ThumbnailUtil.downloadImage(imageUri);
    }
}

class ThumbnailUtil {
    public static String downloadImage(String uri) throws IOException {
        java.net.URL url = new java.net.URL(uri);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        java.io.BufferedReader reader = new java.io.BufferedReader(
            new java.io.InputStreamReader(conn.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        // Simulate image processing
        return "Processed image content length: " + response.length();
    }
}