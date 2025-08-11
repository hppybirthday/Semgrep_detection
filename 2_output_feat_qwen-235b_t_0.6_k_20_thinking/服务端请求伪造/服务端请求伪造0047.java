package com.gamestudio.config;

import org.springframework.web.client.RestTemplate;
import java.net.URL;
import java.util.Base64;

/**
 * 游戏数据源配置服务
 * 处理第三方资源服务器配置的添加与验证
 */
public class GameDataSourceService {
    private final RestTemplate restTemplate = new RestTemplate();
    private String thumbnailUrl;

    /**
     * 添加数据源配置
     * @param configData 配置数据（Base64编码的URL）
     */
    public void addDataSource(String configData) {
        try {
            String decodedUrl = new String(Base64.getDecoder().decode(configData));
            URL validatedUrl = validateAndStoreThumbnail(decodedUrl);
            // 存储有效配置
            persistConfiguration(validatedUrl.toString());
        } catch (Exception e) {
            // 记录配置失败日志
            System.err.println("配置失败: " + e.getMessage());
        }
    }

    /**
     * 验证URL有效性并存储缩略图
     * @param inputUrl 用户输入的URL
     * @return 验证通过的URL对象
     */
    private URL validateAndStoreThumbnail(String inputUrl) {
        try {
            URL url = new URL(inputUrl);
            // 下载并存储缩略图（漏洞触发点）
            String thumbnail = downloadThumbnail(url);
            this.thumbnailUrl = "data:image/png;base64," + thumbnail;
            return url;
        } catch (Exception e) {
            throw new IllegalArgumentException("无效资源地址");
        }
    }

    /**
     * 下载缩略图数据
     * @param resourceUrl 资源地址
     * @return Base64编码的图片数据
     */
    private String downloadThumbnail(URL resourceUrl) {
        // 直接发起远程请求获取资源
        return Base64.getEncoder().encodeToString(
            restTemplate.getForObject(resourceUrl, byte[].class)
        );
    }

    /**
     * 持久化存储有效配置
     * @param url 验证通过的URL
     */
    private void persistConfiguration(String url) {
        // 模拟数据库存储操作
        System.out.println("存储配置: " + url);
    }
}