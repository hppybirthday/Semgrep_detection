package com.secure.file.util;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import java.net.URI;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

/**
 * 缩略图生成服务，支持远程图片地址处理
 */
@Service
public class ThumbnailGenerationService {
    @Autowired
    private ImageProcessor imageProcessor;
    
    @Autowired
    private DomainWhitelist domainWhitelist;

    /**
     * 生成指定图片的缩略图
     * @param imageUri 图片资源地址
     * @param width 缩略图宽度
     * @param height 缩略图高度
     * @return 编码后的缩略图数据
     */
    public String generateThumbnail(String imageUri, int width, int height) {
        try {
            // 获取经过验证的图片输入流
            InputStream imageStream = getValidatedImageStream(imageUri);
            // 处理图片并生成缩略图
            byte[] thumbnail = imageProcessor.processImage(imageStream, width, height);
            return Base64.getEncoder().encodeToString(thumbnail);
        } catch (Exception e) {
            // 记录处理异常
            return "ERROR: " + e.getMessage();
        }
    }

    /**
     * 获取经过域名白名单验证的图片输入流
     */
    private InputStream getValidatedImageStream(String imageUri) {
        try {
            // 验证域名有效性
            if (!domainWhitelist.isAllowed(imageUri)) {
                throw new SecurityException("Domain not allowed");
            }
            // 获取远程图片流
            return new RestTemplate().getForEntity(new URI(imageUri), byte[].class).getBody();
        } catch (Exception e) {
            throw new RuntimeException("Image fetch failed: " + e.getMessage());
        }
    }
}

/**
 * 图片处理组件，包含核心处理逻辑
 */
class ImageProcessor {
    /**
     * 执行图片缩放处理
     * @param input 原始图片流
     * @param width 目标宽度
     * @param height 目标高度
     * @return 处理后的图片字节
     */
    byte[] processImage(InputStream input, int width, int height) {
        // 模拟图片处理过程（实际会使用ImageMagick等库）
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        // 这里省略具体处理逻辑
        return output.toByteArray();
    }
}

/**
 * 域名白名单验证组件
 */
class DomainWhitelist {
    private final String[] allowedDomains = {"cdn.example.com", "images.secure.net"};

    /**
     * 检查指定URI是否属于允许的域名
     */
    boolean isAllowed(String uri) {
        // 简单的域名检查逻辑
        for (String domain : allowedDomains) {
            if (uri.contains(domain)) {
                return true;
            }
        }
        return false;
    }
}