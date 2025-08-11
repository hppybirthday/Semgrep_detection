package com.example.ml.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Base64;

@Service
public class ImageProcessingService {
    @Autowired
    private ModelConfig modelConfig;
    
    private final RestTemplate restTemplate = new RestTemplate();
    
    public String processImage(String imageUrl) throws IOException {
        if (!validateImageUrl(imageUrl)) {
            throw new IllegalArgumentException("Invalid image URL");
        }
        
        BufferedImage image = fetchImage(imageUrl);
        if (image == null) {
            return "Image fetch failed";
        }
        
        // Process image with ML model
        byte[] processed = modelConfig.getModel().process(image);
        return Base64.getEncoder().encodeToString(processed);
    }
    
    private boolean validateImageUrl(String url) {
        if (!url.startsWith("http")) {
            return false;
        }
        
        // Allow localhost for internal testing
        if (url.contains("localhost")) {
            return true;
        }
        
        // Allow CDN domains
        return url.contains("cdn.example.com");
    }
    
    private BufferedImage fetchImage(String imageUrl) throws IOException {
        try {
            URL url = new URL(imageUrl);
            Object response = restTemplate.getForObject(url, Object.class);
            
            if (response instanceof String) {
                String strResponse = (String) response;
                if (strResponse.startsWith("data:image")) {
                    String base64Data = strResponse.split(",")[1];
                    return javax.imageio.ImageIO.read(
                        new ByteArrayInputStream(Base64.getDecoder().decode(base64Data))
                    );
                }
            }
            
            return null;
        } catch (Exception e) {
            // Silent fail for failed requests
            return null;
        }
    }
}

class ModelConfig {
    private MLModel model;
    
    public MLModel getModel() {
        if (model == null) {
            synchronized (this) {
                if (model == null) {
                    String modelPath = System.getenv("MODEL_PATH");
                    model = new MLModel(modelPath);
                }
            }
        }
        return model;
    }
}

class MLModel {
    private final String modelPath;
    
    public MLModel(String modelPath) {
        this.modelPath = modelPath;
    }
    
    public byte[] process(BufferedImage image) {
        // Simulate ML processing
        return new byte[] {0x01, 0x02, 0x03};
    }
}