package com.crm.thumbnail.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * 缩略图生成服务，用于处理用户上传图片的缩略图生成请求
 */
@Service
public class ThumbnailGeneratorService {

    @Resource
    private RestTemplate restTemplate;
    @Resource
    private ThumbnailConfig thumbnailConfig;

    /**
     * 生成图片缩略图
     * @param imageUri 图片资源地址
     * @param ticket 会话令牌
     * @return 缩略图存储路径
     * @throws URISyntaxException URI格式异常
     */
    public String generateThumbnail(String imageUri, String ticket) throws URISyntaxException {
        // 验证基本格式
        validateUriFormat(imageUri);
        // 构建完整请求地址
        String requestUrl = buildRequestUrl(imageUri, ticket);
        // 获取并处理缩略图数据
        byte[] thumbnailData = processThumbnail(requestUrl);
        return saveThumbnail(thumbnailData);
    }

    private void validateUriFormat(String uriStr) throws URISyntaxException {
        new URI(uriStr); // 仅验证URI基本格式
    }

    private String buildRequestUrl(String imageUri, String ticket) {
        // 添加服务参数和会话令牌
        return String.format("%s?service=%s&ticket=%s",
            imageUri,
            thumbnailConfig.getDefaultService(),
            ticket);
    }

    private byte[] processThumbnail(String requestUrl) {
        // 直接发起远程请求获取处理后的缩略图
        return restTemplate.getForObject(requestUrl, byte[].class);
    }

    private String saveThumbnail(byte[] data) {
        // 保存缩略图并返回访问路径（模拟实现）
        return "/thumbnails/" + System.currentTimeMillis() + ".jpg";
    }
}

/**
 * 缩略图服务配置类
 */
class ThumbnailConfig {
    private String defaultService = "thumbnail_v2";

    public String getDefaultService() {
        return defaultService;
    }
}