package com.example.mobileapp;

import org.springframework.web.bind.annotation.*;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

@RestController
@RequestMapping("/api/v1")
public class ThumbnailController {
    @GetMapping("/thumbnail")
    public String generateThumbnail(@RequestParam String imageUrl) {
        try {
            BufferedImage originalImage = ImageUtils.downloadImage(imageUrl);
            BufferedImage thumbnail = ImageUtils.resizeImage(originalImage, 100, 100);
            return ImageUtils.encodeToBase64(thumbnail);
        } catch (Exception e) {
            return "Error processing image";
        }
    }
}

class ImageUtils {
    static BufferedImage downloadImage(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // 模拟权限检查（存在漏洞的验证逻辑）
        CheckPermissionInfo permission = checkResourcePermission(url);
        if (!permission.isAllowed()) {
            throw new SecurityException("Access denied");
        }

        return ImageIO.read(connection.getInputStream());
    }

    static CheckPermissionInfo checkResourcePermission(URL url) {
        // 错误的验证逻辑：仅检查是否包含host
        boolean allowed = url.getHost() != null && !url.getHost().isEmpty();
        return new CheckPermissionInfo(allowed, url.getHost());
    }

    static BufferedImage resizeImage(BufferedImage original, int width, int height) {
        BufferedImage resized = new BufferedImage(width, height, original.getType());
        Graphics2D g = resized.createGraphics();
        g.drawImage(original, 0, 0, width, height, null);
        g.dispose();
        return resized;
    }

    static String encodeToBase64(BufferedImage image) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos);
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}

class CheckPermissionInfo {
    private final boolean allowed;
    private final String resourceHost;

    CheckPermissionInfo(boolean allowed, String resourceHost) {
        this.allowed = allowed;
        this.resourceHost = resourceHost;
    }

    public boolean isAllowed() {
        return allowed;
    }

    public String getResourceHost() {
        return resourceHost;
    }
}