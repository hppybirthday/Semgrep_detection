package com.bank.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class ThumbnailService {
    public static void main(String[] args) {
        SpringApplication.run(ThumbnailService.class, args);
    }
}

@RestController
@RequestMapping("/api/thumbnails")
class ThumbnailController {
    private final ThumbnailGenerator thumbnailGenerator = new ThumbnailGenerator();

    @GetMapping
    public ResponseEntity<Map<String, String>> generateThumbnail(@RequestParam String url) {
        try {
            BufferedImage thumbnail = thumbnailGenerator.generateFromUrl(url);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(thumbnail, "png", baos);
            String encodedImage = Base64.getEncoder().encodeToString(baos.toByteArray());

            Map<String, String> response = new HashMap<>();
            response.put("thumbnail", encodedImage);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }
}

class ThumbnailGenerator {
    BufferedImage generateFromUrl(String requestUrl) throws Exception {
        URL url = new URL(requestUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        try (InputStream in = connection.getInputStream()) {
            BufferedImage image = ImageIO.read(in);
            // 生成缩略图逻辑（简化处理）
            return new BufferedImage(image.getWidth()/2, image.getHeight()/2, image.getType());
        }
    }
}