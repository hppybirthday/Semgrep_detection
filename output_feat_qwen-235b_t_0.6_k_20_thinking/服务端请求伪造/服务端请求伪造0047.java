package com.example.thumbnail.service;

import com.example.thumbnail.dto.ThumbnailRequest;
import com.example.thumbnail.dto.ThumbnailResponse;
import org.springframework.stereotype.Service;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.HttpURLConnection;

@Service
public class LocalThumbnailService {
    public ThumbnailResponse generateThumbnail(ThumbnailRequest request) {
        try {
            // 漏洞点：直接使用用户输入的URL
            URL imageUrl = new URL(request.getUrl());
            HttpURLConnection connection = (HttpURLConnection) imageUrl.openConnection();
            connection.setRequestMethod("GET");
            
            try (InputStream in = connection.getInputStream()) {
                BufferedImage image = ImageIO.read(in);
                BufferedImage thumbnail = resizeImage(image, 100, 100);
                
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ImageIO.write(thumbnail, "png", baos);
                
                return new ThumbnailResponse(baos.toByteArray(), "image/png");
            }
        } catch (Exception e) {
            throw new RuntimeException("Thumbnail generation failed", e);
        }
    }

    private BufferedImage resizeImage(BufferedImage originalImage, int width, int height) {
        BufferedImage resizedImage = new BufferedImage(width, height, originalImage.getType());
        resizedImage.getGraphics().drawImage(originalImage.getScaledInstance(width, height, java.awt.Image.SCALE_SMOOTH), 0, 0, null);
        return resizedImage;
    }
}

// Controller层示例
@RestController
@RequestMapping("/thumbnail")
class ThumbnailController {
    @Autowired
    private LocalThumbnailService thumbnailService;

    @GetMapping
    public ResponseEntity<byte[]> createThumbnail(@RequestParam String url) {
        ThumbnailResponse response = thumbnailService.generateThumbnail(new ThumbnailRequest(url));
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_TYPE, response.contentType())
            .body(response.imageData());
    }
}

// DTO类
record ThumbnailRequest(String url) {}
record ThumbnailResponse(byte[] imageData, String contentType) {}