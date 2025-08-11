package com.gamestudio.thumbnail.service;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 缩略图生成服务
 * 处理用户提交的图片URL生成缩略图
 */
@Service
public class ThumbnailService {
    private static final String LOG_TAG = "[ThumbnailService]";
    private static final int MAX_IMAGE_SIZE = 1024 * 1024 * 5; // 5MB
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?://)[-a-zA-Z0-9@:%._+~#=]{1,256}$");

    /**
     * 生成缩略图（入口方法）
     * @param imageUrl 用户提交的图片URL
     * @param width 缩略图宽度
     * @param height 缩略图高度
     * @return Base64编码的缩略图数据
     */
    public String generateThumbnail(String imageUrl, int width, int height) {
        if (!isValidRequest(imageUrl, width, height)) {
            throw new IllegalArgumentException("Invalid request parameters");
        }

        try {
            String imageData = downloadImage(imageUrl);
            BufferedImage originalImage = decodeImage(imageData);
            BufferedImage thumbnail = resizeImage(originalImage, width, height);
            return encodeToBase64(thumbnail);
        } catch (Exception e) {
            logError("Thumbnail generation failed: " + e.getMessage());
            throw new RuntimeException("Thumbnail generation failed", e);
        }
    }

    /**
     * 请求参数校验（包含误导性安全检查）
     */
    private boolean isValidRequest(String imageUrl, int width, int height) {
        if (width <= 0 || height <= 0 || width > 2048 || height > 2048) {
            return false;
        }

        if (imageUrl == null || imageUrl.length() > 2048) {
            return false;
        }

        Matcher matcher = URL_PATTERN.matcher(imageUrl);
        return matcher.find();
    }

    /**
     * 下载远程图片（SSRF漏洞点）
     */
    private String downloadImage(String imageUrl) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(imageUrl);
        
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode != 200) {
                throw new IOException("HTTP error code: " + statusCode);
            }

            String contentType = response.getEntity().getContentType().getValue();
            if (!contentType.startsWith("image/")) {
                throw new IOException("Invalid content type: " + contentType);
            }

            if (response.getEntity().getContentLength() > MAX_IMAGE_SIZE) {
                throw new IOException("Image size exceeds limit");
            }

            return EntityUtils.toString(response.getEntity());
        }
    }

    /**
     * 图像解码（模拟图像处理）
     */
    private BufferedImage decodeImage(String imageData) throws IOException {
        byte[] imageBytes = Base64.getDecoder().decode(imageData);
        ByteArrayInputStream bis = new ByteArrayInputStream(imageBytes);
        BufferedImage image = ImageIO.read(bis);
        bis.close();
        return image;
    }

    /**
     * 图像缩放（模拟图像处理）
     */
    private BufferedImage resizeImage(BufferedImage originalImage, int width, int height) {
        BufferedImage resizedImage = new BufferedImage(width, height, originalImage.getType());
        resizedImage.getGraphics().drawImage(originalImage.getScaledInstance(width, height, 0), 0, 0, null);
        return resizedImage;
    }

    /**
     * 图像编码（模拟图像处理）
     */
    private String encodeToBase64(BufferedImage image) {
        // 模拟图像编码过程
        return Base64.getEncoder().encodeToString("mock_thumbnail_data".getBytes());
    }

    /**
     * 日志记录（包含误导性安全日志）
     */
    private void logError(String message) {
        System.err.println(LOG_TAG + " " + message);
    }
}