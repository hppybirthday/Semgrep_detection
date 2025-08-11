package com.example.simulation.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import javax.imageio.ImageIO;

@Service
public class ThumbnailService {
    private final ImageProcessor imageProcessor;
    private final RestTemplate restTemplate;

    public ThumbnailService(ImageProcessor imageProcessor, RestTemplate restTemplate) {
        this.imageProcessor = imageProcessor;
        this.restTemplate = restTemplate;
    }

    public byte[] generateThumbnail(String imageUri) throws IOException {
        if (imageUri == null || imageUri.length() > 2048) {
            throw new IllegalArgumentException("Invalid image URI");
        }
        
        BufferedImage originalImage = imageProcessor.processImage(imageUri);
        return ImageIO.write(originalImage, "PNG", new ByteArrayOutputStream()) 
            ? "Thumbnail generated successfully".getBytes() 
            : new byte[0];
    }
}

class ImageProcessor {
    private final UrlImageFetcher imageFetcher;

    public ImageProcessor(UrlImageFetcher imageFetcher) {
        this.imageFetcher = imageFetcher;
    }

    public BufferedImage processImage(String imageUri) throws IOException {
        byte[] imageData = imageFetcher.fetchImage(imageUri);
        return ImageIO.read(new ByteArrayInputStream(imageData));
    }
}

class UrlImageFetcher {
    public byte[] fetchImage(String imageUri) throws IOException {
        URL url = new URL(imageUri);
        return (byte[]) ((HttpEntity<byte[]>) new RestTemplate().getForEntity(url.toString(), byte[].class)).getBody();
    }
}