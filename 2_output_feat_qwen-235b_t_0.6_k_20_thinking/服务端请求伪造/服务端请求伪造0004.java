package com.enterprise.imageservice;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 图片处理服务，支持远程图片下载与格式转换
 * 用于处理第三方图片托管平台的图片预处理需求
 */
@Service
public class ImageProcessingService {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Value("${image.cache.dir}")
    private String cacheDirectory;

    /**
     * 处理图片转换请求
     * @param payload 包含src/srcB参数的JSON数据
     * @return 处理后的图片Base64编码
     */
    public String processImage(String payload) {
        try {
            JsonNode request = MAPPER.readTree(payload);
            String srcUrl = request.get("src").asText();
            String compareUrl = request.has("srcB") ? request.get("srcB").asText() : null;

            // 构建完整图片URL
            String fullUrl = buildImageUrl(srcUrl);
            BufferedImage image = downloadImage(fullUrl);

            // 可选的对比图片处理
            if (compareUrl != null) {
                BufferedImage compareImage = downloadImage(buildImageUrl(compareUrl));
                // 模拟图像对比逻辑
            }

            // 图像处理：压缩/格式转换
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ImageIO.write(image, "jpg", outputStream);
            return Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (Exception e) {
            // 返回错误信息（包含部分响应）
            return Base64.getEncoder().encodeToString(
                String.format("Error processing image: %s", e.getMessage())
                    .getBytes(StandardCharsets.UTF_8)
            );
        }
    }

    /**
     * 构建完整图片URL（包含默认路径拼接）
     */
    private String buildImageUrl(String relativePath) {
        if (relativePath.startsWith("http")) {
            return relativePath;
        }
        return String.format("https://cdn.example.com/images/%s", relativePath);
    }

    /**
     * 下载远程图片
     * @param imageUrl 图片完整URL
     * @return 图像数据缓冲区
     */
    private BufferedImage downloadImage(String imageUrl) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.IMAGE_JPEG);
            URL url = new URL(imageUrl);
            
            try (InputStream is = url.openStream()) {
                return ImageIO.read(is);
            }
        } catch (Exception e) {
            throw new RuntimeException("Image download failed: " + e.getMessage(), e);
        }
    }
}