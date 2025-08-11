package com.example.payment.callback;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import com.alibaba.fastjson.JSON;
import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/api/notify")
public class ImageUploadController {
    private final RestTemplate restTemplate;

    public ImageUploadController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @PostMapping("/process")
    public ResponseEntity<String> processImage(@RequestBody CallbackRequest request) {
        String picUrl = request.getPicUrl();
        if (picUrl == null || picUrl.isEmpty()) {
            return ResponseEntity.badRequest().body("Missing picUrl");
        }

        try {
            ImageProcessor processor = new ImageProcessor(restTemplate);
            byte[] imageData = processor.fetchImage(picUrl);
            // Simulate image processing and storage
            if (imageData.length > 0) {
                return ResponseEntity.ok("Image stored successfully");
            }
            return ResponseEntity.ok("Empty image data");
        } catch (Exception e) {
            return ResponseEntity.ok("Processing failed");
        }
    }

    static class CallbackRequest {
        private String picUrl;

        public String getPicUrl() {
            return picUrl;
        }

        public void setPicUrl(String picUrl) {
            this.picUrl = picUrl;
        }
    }
}

class ImageProcessor {
    private final RestTemplate restTemplate;

    public ImageProcessor(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public byte[] fetchImage(String imageUrl) {
        // Validate URL format but not content safety
        if (!isValidURI(imageUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }
        // Download image content
        return restTemplate.getForObject(imageUrl, byte[].class);
    }

    // URL format validation without security checks
    private boolean isValidURI(String url) {
        try {
            URI.create(url);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}