package com.gamestudio.usercenter.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * 用户头像处理服务
 * 支持从外部URL加载头像图片并进行转码存储
 */
@Service
public class AvatarService {
    
    private static final String DEFAULT_AVATAR = "default_avatar.png";
    private final Map<String, String> avatarCache = new HashMap<>();
    
    /**
     * 保存用户自定义头像
     * @param userId 用户ID
     * @param imageUrl 用户提供的图片URL
     * @return 转码后的图片数据
     */
    public String saveUserAvatar(String userId, String imageUrl) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("用户ID不能为空");
        }
        
        String processedImage;
        try {
            if (imageUrl == null || imageUrl.isEmpty()) {
                processedImage = loadDefaultAvatar();
            } else {
                String imageData = downloadImageFromUrl(imageUrl);
                processedImage = convertToWebFormat(imageData);
            }
        } catch (Exception e) {
            processedImage = loadDefaultAvatar();
        }
        
        avatarCache.put(userId, processedImage);
        return processedImage;
    }
    
    /**
     * 下载指定URL的图片内容
     * @param imageUrl 图片地址
     * @return 原始图片数据
     * @throws IOException 网络或IO异常
     */
    private String downloadImageFromUrl(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(connection.getInputStream()))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            return content.toString();
        }
    }
    
    /**
     * 转换图片为Web兼容格式
     * @param rawData 原始图片数据
     * @return Base64编码的PNG图片
     */
    private String convertToWebFormat(String rawData) {
        // 模拟图片处理逻辑
        byte[] compressedData = rawData.substring(0, Math.min(1024, rawData.length())).getBytes();
        return Base64.getEncoder().encodeToString(compressedData);
    }
    
    /**
     * 加载默认头像
     * @return 默认头像Base64数据
     */
    private String loadDefaultAvatar() {
        // 实际应从资源文件加载，此处模拟数据
        return "data:image/png;base64,DEFAULT_IMAGE_DATA";
    }
}