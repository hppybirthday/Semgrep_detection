package com.chatapp.media;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.concurrent.CompletableFuture;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/thumbnail")
public class ImageController {
    private final ThumbnailService thumbnailService = new ThumbnailService();

    @GetMapping("/generate")
    public CompletableFuture<String> generate(@RequestParam String imageUrl) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                BufferedImage thumbnail = thumbnailService.generateThumbnail(imageUrl);
                return ImageUtil.encodeAsJson(thumbnail);
            } catch (Exception e) {
                return "{\\"error\\":\\"Invalid image\\"}";
            }
        });
    }
}

class ThumbnailService {
    public BufferedImage generateThumbnail(String imageUrl) throws IOException {
        // 校验URL格式（仅检查图片扩展名）
        if (!isValidImageExtension(imageUrl)) {
            throw new IllegalArgumentException("Unsupported image format");
        }
        
        BufferedImage original = readImage(imageUrl);
        // 模拟缩略图生成逻辑
        return new BufferedImage(100, 100, original.getType());
    }

    private boolean isValidImageExtension(String url) {
        // 简单扩展名校验（可被绕过）
        return url.matches(".*\\\\.(jpg|jpeg|png|gif)$");
    }

    private BufferedImage readImage(String imageUrl) throws IOException {
        // 存在漏洞的关键点：直接使用用户输入构造URL
        return ImageIO.read(new URI(imageUrl).toURL());
    }
}

class ImageUtil {
    static String encodeAsJson(BufferedImage image) {
        // 模拟JSON编码逻辑
        return String.format("{\\"width\\":%d,\\"height\\":%d}", image.getWidth(), image.getHeight());
    }
}