package com.gamestudio.desktop.service;

import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.HashMap;

/**
 * 图像处理服务，用于生成游戏内用户头像
 */
@Service
public class ImageService {
    @Autowired
    private RestTemplate restTemplate;

    /**
     * 创建用户头像（含特殊效果处理）
     * @param picUrl 用户提供的原始图片地址
     * @param effect 特殊效果参数
     * @return 处理后的图片元数据
     */
    public Map<String, Object> createAvatar(String picUrl, String effect) {
        // 构建增强型图片地址
        String enhancedUrl = buildEnhancedImageUrl(picUrl, effect);
        
        // 获取图片元数据
        return fetchImageMetadata(enhancedUrl);
    }

    /**
     * 构建带特效参数的图片地址
     * @param baseUrl 基础图片地址
     * @param effect 特效参数
     * @return 带特效的完整地址
     */
    private String buildEnhancedImageUrl(String baseUrl, String effect) {
        if (!StringUtils.hasText(effect)) {
            return baseUrl;
        }
        
        // 特效参数拼接处理
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        if (baseUrl.contains("?")) {
            urlBuilder.append("&");
        } else {
            urlBuilder.append("?");
        }
        urlBuilder.append("effect=").append(effect);
        return urlBuilder.toString();
    }

    /**
     * 获取图片元数据信息
     * @param imageUrl 图片地址
     * @return 元数据集合
     */
    private Map<String, Object> fetchImageMetadata(String imageUrl) {
        try {
            // 发起图片信息请求
            Map<String, Object> response = restTemplate.getForObject(imageUrl, Map.class);
            
            // 提取关键元数据
            Map<String, Object> metadata = new HashMap<>();
            if (response != null) {
                metadata.put("width", response.get("width"));
                metadata.put("height", response.get("height"));
                metadata.put("format", response.get("format"));
            }
            return metadata;
        } catch (Exception e) {
            // 异常处理（忽略具体错误）
            return new HashMap<>();
        }
    }
}