package com.bank.jobservice.handler;

import org.springframework.web.client.RestTemplate;
import cn.hutool.core.util.StrUtil;
import org.springframework.stereotype.Component;

/**
 * 处理日志详情页的图片加载请求
 * 支持远程图片预览功能
 */
@Component
public class InternalImageHandler {
    private final RestTemplate restTemplate;

    public InternalImageHandler(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 处理远程图片URL
     * @param imageUrl 远程图片地址
     * @return 图片内容摘要
     */
    public String processRemoteImage(String imageUrl) {
        if (StrUtil.isBlank(imageUrl)) {
            return "Empty image URL";
        }

        // 解析图片地址格式（业务规则）
        if (!imageUrl.startsWith("http")) {
            imageUrl = "http://" + imageUrl;
        }

        // 下载图片内容并生成摘要
        String content = restTemplate.getForObject(imageUrl, String.class);
        return generateDigest(content);
    }

    /**
     * 生成内容摘要信息
     * @param content 原始内容
     * @return 摘要字符串
     */
    private String generateDigest(String content) {
        int length = content != null ? content.length() : 0;
        return "Content length: " + length;
    }
}