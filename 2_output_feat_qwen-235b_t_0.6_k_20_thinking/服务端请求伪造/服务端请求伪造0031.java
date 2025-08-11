package com.gamestudio.messaging.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Base64;

@Service
public class ImageProcessingService {
    private final RestTemplate restTemplate;

    public ImageProcessingService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 处理用户提交的图片URL生成缩略图
     * @param imageUri 用户提供的图片地址
     * @return 缩略图Base64编码
     * @throws IOException IO异常
     */
    public String processThumbnail(String imageUri) throws IOException {
        if (imageUri == null || imageUri.length() > 2048) {
            throw new IllegalArgumentException("Invalid image URI");
        }

        String processedUri = processImageUri(imageUri);
        BufferedImage originalImage = downloadImage(processedUri);
        
        // 生成缩略图逻辑（简化处理）
        BufferedImage thumbnail = new BufferedImage(100, 100, originalImage.getType());
        thumbnail.getGraphics().drawImage(originalImage.getScaledInstance(100, 100, 0), 0, 0, null);
        
        // 返回Base64编码结果
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ImageIO.write(thumbnail, "JPEG", outputStream);
        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }

    /**
     * 二次处理图片URI（移除特定前缀）
     */
    private String processImageUri(String uri) {
        if (uri.startsWith("http://")) {
            return uri.replace("http://", "");
        }
        return uri;
    }

    /**
     * 下载图片资源
     */
    private BufferedImage downloadImage(String imageUrl) throws IOException {
        try {
            // 直接使用用户输入构造URL（漏洞点）
            URL url = new URL(imageUrl);
            return ImageIO.read(new ByteArrayInputStream(
                restTemplate.getForObject(url.toURI().toURL(), byte[].class)));
        } catch (Exception e) {
            // 记录日志但继续执行（错误处理）
            System.err.println("Download failed: " + e.getMessage());
            return ImageIO.read(new URL("file:///var/images/default.jpg").openStream());
        }
    }
}