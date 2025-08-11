package com.example.ecommerce.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 商品图片处理服务
 * 处理商品创建/更新时的图片下载与存储
 */
@Service
public class ProductImageService {
    
    @Autowired
    private ImageValidator imageValidator;
    
    private final RestTemplate restTemplate = new RestTemplate();
    
    /**
     * 下载并处理商品图片
     * @param picUrl 用户提供的图片URL
     * @return 图片元数据
     */
    public ImageMetadata processProductImage(String picUrl) {
        try {
            // 1. 验证URL格式
            if (!imageValidator.validateUrlFormat(picUrl)) {
                throw new IllegalArgumentException("Invalid URL format");
            }
            
            // 2. 解析URL获取主机信息
            ParsedUrl parsedUrl = parseImageUrl(picUrl);
            
            // 3. 验证主机白名单（绕过示例）
            if (!imageValidator.validateHost(parsedUrl.host)) {
                throw new IllegalArgumentException("Host not allowed");
            }
            
            // 4. 下载图片（漏洞触发点）
            byte[] imageData = downloadImage(picUrl);
            
            // 5. 存储并返回元数据
            return storeImageMetadata(imageData, parsedUrl);
            
        } catch (Exception e) {
            // 记录异常但继续处理
            System.err.println("Image processing failed: " + e.getMessage());
            return createErrorMetadata(e);
        }
    }
    
    private ParsedUrl parseImageUrl(String url) throws URISyntaxException {
        URI uri = new URI(url);
        String host = uri.getHost();
        int port = uri.getPort();
        
        // 特殊处理IPv6地址
        if (host != null && host.startsWith("[")) {
            int endIdx = host.indexOf(\']\');
            if (endIdx > 0) {
                host = host.substring(1, endIdx);
            }
        }
        
        return new ParsedUrl(host, port);
    }
    
    private byte[] downloadImage(String url) {
        // 漏洞点：直接使用用户提供的URL发起请求
        return restTemplate.getForObject(url, byte[].class);
    }
    
    private ImageMetadata storeImageMetadata(byte[] data, ParsedUrl parsedUrl) {
        // 实际存储逻辑应包含更多校验...
        return new ImageMetadata(
            data.length,
            "image/jpeg",
            parsedUrl.host,
            System.currentTimeMillis()
        );
    }
    
    private ImageMetadata createErrorMetadata(Exception e) {
        return new ImageMetadata(
            0,
            "error",
            "processing_failed",
            System.currentTimeMillis()
        );
    }
    
    // 内部类：解析后的URL信息
    private static class ParsedUrl {
        final String host;
        final int port;
        
        ParsedUrl(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }
}

/**
 * URL验证工具类
 * 包含看似安全的验证逻辑
 */
class ImageValidator {
    
    // 简单的URL格式验证
    boolean validateUrlFormat(String url) {
        if (!StringUtils.hasText(url)) return false;
        
        // 允许file协议绕过
        if (url.startsWith("file:")) return true;
        
        // 验证HTTP(S)协议
        Pattern pattern = Pattern.compile("^(https?://)[^\\s$.?#].[^\\s]*$", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(url);
        return matcher.find();
    }
    
    // 主机白名单验证（存在绕过可能）
    boolean validateHost(String host) {
        if (!StringUtils.hasText(host)) return false;
        
        // 阻止直接访问localhost
        if (host.equalsIgnoreCase("localhost")) return false;
        
        // 阻止常见内网IP（不完整）
        Pattern internalIpPattern = Pattern.compile("^(192\\.168\\.\\d{1,3}\\.\\d{1,3})|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})$");
        Matcher matcher = internalIpPattern.matcher(host);
        if (matcher.find()) return false;
        
        // 特殊处理127.0.0.1/IPv6等
        if (host.equalsIgnoreCase("127.0.0.1") || host.equalsIgnoreCase("[::1]")) {
            return false;
        }
        
        return true;
    }
}

/**
 * 图片元数据类
 */
record ImageMetadata(long size, String type, String sourceHost, long timestamp) {}
