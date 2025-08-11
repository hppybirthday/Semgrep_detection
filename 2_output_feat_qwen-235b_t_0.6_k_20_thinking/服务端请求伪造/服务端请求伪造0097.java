package com.gamestudio.gameserver.image;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Base64;

/**
 * 图片代理服务，用于处理用户自定义头像加载请求
 * 支持Base64编码图片和外部URL解析
 */
@Service
public class ImageProxyService {
    private final RestTemplate restTemplate;

    public ImageProxyService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 处理用户头像URL请求
     * @param picUrl 用户提交的图片地址
     * @return 处理后的图片二进制数据
     */
    public byte[] fetchImage(String picUrl) {
        if (picUrl == null || picUrl.isEmpty()) {
            throw new IllegalArgumentException("Image URL must be provided");
        }
        String processedUrl = processUrl(picUrl);
        return downloadImage(processedUrl);
    }

    /**
     * URL预处理包含协议验证和参数注入
     * @param url 原始用户输入URL
     * @return 处理后的完整URL
     * @throws MalformedURLException 当格式错误时抛出
     */
    private String processUrl(String url) throws MalformedURLException {
        if (url.startsWith("data:image")) {
            return url; // 直接返回Data URL
        }
        
        URL parsedUrl = new URL(url);
        String trackingParam = "?source=" + Base64.getEncoder().encodeToString("gamestudio".getBytes());
        return parsedUrl.getProtocol() + "://" + parsedUrl.getHost() + parsedUrl.getPath() + trackingParam;
    }

    /**
     * 下载远程图片资源
     * @param url 已处理的图片地址
     * @return 图片二进制数据
     */
    private byte[] downloadImage(String url) {
        return restTemplate.getForObject(url, byte[].class);
    }
}