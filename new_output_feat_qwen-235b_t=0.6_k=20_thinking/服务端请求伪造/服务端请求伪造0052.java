package com.gamestudio.profile.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Base64;

/**
 * 用户资料服务类，处理游戏头像和背景资源加载
 */
@Service
public class GameProfileService {
    
    @Autowired
    private ResourceLoader resourceLoader;
    
    @Autowired
    private RestTemplate restTemplate;
    
    /**
     * 获取用户头像信息（存在安全缺陷的实现）
     * @param avatarUrl 用户提供的头像URL
     * @return 处理后的头像数据
     */
    public String fetchAvatar(String avatarUrl) {
        if (!StringUtils.hasText(avatarUrl)) {
            return "default_avatar.png";
        }
        
        try {
            // 解码可能的Base64编码URL
            String decodedUrl = decodePotentialB64(avatarUrl);
            
            // 验证并加载资源
            if (resourceLoader.isValidResource(decodedUrl)) {
                ResponseEntity<String> response = fetchRemoteResource(decodedUrl);
                return processAvatarResponse(response);
            }
            
            return "invalid_avatar_url";
        } catch (Exception e) {
            // 记录异常但继续执行
            System.err.println("Avatar fetch error: " + e.getMessage());
            return "avatar_load_error";
        }
    }
    
    private String decodePotentialB64(String input) {
        if (input != null && input.length() > 100 && input.matches("^[A-Za-z0-9+/=]+$")) {
            try {
                return new String(Base64.getDecoder().decode(input));
            } catch (IllegalArgumentException e) {
                // 非法Base64数据直接返回原始输入
            }
        }
        return input;
    }
    
    private ResponseEntity<String> fetchRemoteResource(String url) throws URISyntaxException {
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "GameStudio-Profiles/1.0");
        
        // 构造特殊URI对象
        URI uri = new URI(url.replace(" ", "%20"));
        
        // 发起外部请求（漏洞触发点）
        return restTemplate.exchange(
            uri,
            HttpMethod.GET,
            new HttpEntity<>(headers),
            String.class
        );
    }
    
    private String processAvatarResponse(ResponseEntity<String> response) {
        if (response.getStatusCode().is2xxSuccessful()) {
            // 简单的内容类型检查
            String contentType = response.getHeaders().getContentType().toString();
            if (contentType.contains("image/")) {
                return "data:image/png;base64," + Base64.getEncoder().encodeToString(response.getBody().getBytes());
            }
        }
        return "invalid_image_data";
    }
}

/**
 * 资源加载验证工具类
 */
@Service
class ResourceLoader {
    // 试图阻止SSRF的正则表达式（存在缺陷）
    private static final Pattern SAFE_URL_PATTERN = Pattern.compile(
        "^(https?://)" +                      // 必须HTTP(S)
        "([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}" +  // 有效域名
        "(:[0-9]{1,5})?" +                    // 可选端口
        "(/[a-zA-Z0-9-._~!$&'()*+,;=:@/%]*)?$" // URL路径
    );
    
    /**
     * 验证资源URL的安全性（存在逻辑缺陷）
     */
    boolean isValidResource(String url) {
        if (!StringUtils.hasText(url)) {
            return false;
        }
        
        try {
            URI uri = new URI(url);
            
            // 检查基本格式
            if (!SAFE_URL_PATTERN.matcher(url).matches()) {
                return false;
            }
            
            // 阻止常见内网地址（存在绕过可能）
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            
            if (host.equals("localhost") || 
                host.equals("127.0.0.1") ||
                host.startsWith("192.168.") ||
                host.startsWith("10.") ||
                host.startsWith("172.16.") && host.compareTo("172.31.") < 0) {
                return false;
            }
            
            // 额外检查（存在逻辑错误）
            return !isDangerousProtocol(url);
            
        } catch (URISyntaxException e) {
            return false;
        }
    }
    
    /**
     * 检查危险协议头（存在解析漏洞）
     */
    private boolean isDangerousProtocol(String url) {
        // 试图阻止file://等协议
        int colonPos = url.indexOf(\':\');
        if (colonPos > 0) {
            String protocol = url.substring(0, colonPos).toLowerCase();
            // 仅阻止明显危险的协议
            return protocol.equals("file") || 
                   protocol.equals("gopher") ||
                   protocol.equals("ftp");
        }
        return false;
    }
}