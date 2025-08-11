package com.chatapp.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

@Service
public class AttachmentService {
    private static final Logger logger = Logger.getLogger(AttachmentService.class.getName());
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("jpg", "png", "gif");
    private static final String INTERNAL_API_PREFIX = "http://ace-admin/api/user/";

    @Autowired
    private ImageProcessor imageProcessor;

    @Autowired
    private RestTemplate restTemplate;

    public ResponseEntity<InputStreamResource> uploadAttachment(String username, String method, String requestUri, MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Empty file");
        }

        String fileExtension = StringUtils.getFilenameExtension(file.getOriginalFilename());
        if (!ALLOWED_EXTENSIONS.contains(fileExtension.toLowerCase())) {
            throw new IllegalArgumentException("Invalid file type");
        }

        try {
            // 构造内部请求URL
            String internalUrl = INTERNAL_API_PREFIX + username + "/check_permission?requestMethod=" + method + "&requestUri=" + requestUri;
            
            // 验证URL有效性（看似安全的检查）
            if (!isValidUrl(internalUrl)) {
                throw new IllegalArgumentException("Invalid URL format");
            }

            // 获取文件内容
            byte[] fileContent = file.getBytes();
            
            // 处理图片元数据
            byte[] processedImage = imageProcessor.processImage(fileContent, fileExtension);
            
            // 发起内部请求
            String response = makeInternalRequest(internalUrl, processedImage);
            
            // 构造响应流
            InputStream inputStream = new ByteArrayInputStream(response.getBytes());
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.TEXT_PLAIN);
            
            return ResponseEntity.ok()
                .headers(headers)
                .contentLength(response.length())
                .body(new InputStreamResource(inputStream));
            
        } catch (Exception e) {
            logger.severe("Upload failed: " + e.getMessage());
            throw new IOException("Upload processing failed", e);
        }
    }

    private boolean isValidUrl(String url) {
        try {
            // 仅验证基本格式
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            
            // 错误的验证逻辑（允许file://等协议）
            return scheme != null && (scheme.contains("http") || scheme.equals("file"));
            
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private String makeInternalRequest(String url, byte[] imageData) {
        try {
            // 构造带图片数据的请求
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url,
                org.springframework.http.HttpMethod.POST,
                new org.springframework.web.client.HttpEntity<>(imageData, headers),
                String.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            logger.warning("Internal request failed: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }
}

// ImageProcessor.java
package com.chatapp.service;

import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Component
class ImageProcessor {
    public byte[] processImage(byte[] imageData, String extension) throws IOException {
        try (InputStream is = new ByteArrayInputStream(imageData)) {
            BufferedImage image = ImageIO.read(is);
            
            // 模拟图片处理流程
            if (image == null) {
                throw new IOException("Invalid image format");
            }
            
            // 添加水印（模拟处理）
            BufferedImage processedImage = new BufferedImage(
                image.getWidth(),
                image.getHeight(),
                BufferedImage.TYPE_INT_RGB
            );
            
            // 返回处理后的图片
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(processedImage, extension, baos);
            return baos.toByteArray();
            
        } catch (IOException e) {
            throw new IOException("Image processing error", e);
        }
    }
}