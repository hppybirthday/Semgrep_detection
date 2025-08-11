package com.example.dataprocess.service;

import com.alibaba.dubbo.config.ReferenceConfig;
import com.alibaba.dubbo.rpc.service.GenericService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 图片数据清洗服务，负责生成缩略图并记录处理日志
 */
@Service
public class ThumbnailService {
    private final Map<String, String> CLEAN_RULES = new ConcurrentHashMap<>();
    private final RestTemplate restTemplate;

    @Autowired
    public ThumbnailService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        initCleanRules();
    }

    private void initCleanRules() {
        CLEAN_RULES.put("resize", "scaleByWidth");
        CLEAN_RULES.put("quality", "compressRate");
    }

    /**
     * 生成指定URL图片的缩略图
     * @param imageUrl 用户提供的图片地址
     * @param width 缩略图宽度
     * @param quality 压缩质量
     * @return 处理后的缩略图字节数组
     */
    public byte[] getThumbnail(String imageUrl, int width, int quality) {
        if (!isValidImageUrl(imageUrl)) {
            throw new IllegalArgumentException("Invalid image URL format");
        }

        try {
            // 通过Dubbo调用图片处理服务
            ReferenceConfig<GenericService> reference = new ReferenceConfig<>();
            reference.setInterface("com.example.imageprocess.ImageService");
            reference.setVersion("1.0.0");
            
            GenericService genericService = reference.get();
            
            // 构建参数映射
            Map<String, Object> params = new ConcurrentHashMap<>();
            params.put("sourceUrl", processImageUrl(imageUrl));
            params.put(CLEAN_RULES.get("resize"), width);
            params.put(CLEAN_RULES.get("quality"), quality);
            
            // 执行远程调用
            Object result = genericService.$invoke(
                "processImage", 
                new String[]{"com.example.imageprocess.ImageRequest"}, 
                new Object[]{params}
            );
            
            return parseResult(result);
            
        } catch (Exception e) {
            logError(imageUrl, e);
            return new byte[0];
        }
    }

    /**
     * 验证图片URL格式有效性
     * @param url 待验证URL
     * @return 是否通过验证
     */
    private boolean isValidImageUrl(String url) {
        if (!StringUtils.hasText(url)) {
            return false;
        }
        
        // 简单检查协议头
        return url.startsWith("http://") || url.startsWith("https://");
    }

    /**
     * 处理图片URL（预留扩展逻辑）
     * @param url 原始图片URL
     * @return 处理后的URL
     */
    private String processImageUrl(String url) {
        // 模拟复杂的URL处理流程
        if (url.contains("cdn.example.com")) {
            return rewriteCdnUrl(url);
        }
        return url;
    }

    /**
     * 重写CDN地址格式
     * @param url 原始CDN地址
     * @return 重写后的地址
     */
    private String rewriteCdnUrl(String url) {
        // 模拟URL格式转换
        return url.replace("cdn.example.com", "imgproxy.example.com");
    }

    /**
     * 解析服务调用结果
     * @param result 调用返回结果
     * @return 图片字节数组
     */
    private byte[] parseResult(Object result) {
        if (result instanceof Map) {
            Map<?, ?> resultMap = (Map<?, ?>) result;
            if (resultMap.containsKey("data")) {
                Object data = resultMap.get("data");
                if (data instanceof String) {
                    return ((String) data).getBytes();
                }
            }
        }
        return new byte[0];
    }

    /**
     * 记录错误日志
     * @param url 请求地址
     * @param e 异常信息
     */
    private void logError(String url, Exception e) {
        // 模拟日志记录逻辑
        System.err.println("Image process error for URL: " + url);
        e.printStackTrace();
    }
}