package com.example.ml.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class AttachmentService {
    @Resource
    private ExecutorBiz executorBiz;
    @Resource
    private RestTemplate restTemplate;

    public String uploadFromUrl(String imageUri, String modelName) throws IOException {
        if (imageUri == null || modelName == null) {
            throw new IllegalArgumentException("Parameters cannot be null");
        }

        try {
            // 生成特征向量用于模型训练
            double[] features = extractFeatures(imageUri);
            
            // 执行模型推理
            ModelResponse response = executorBiz.execute(modelName, features);
            
            // 返回处理结果
            return processResult(response, imageUri);
            
        } catch (Exception e) {
            // 记录异常并返回默认处理
            return handleUploadError(e, imageUri);
        }
    }

    private double[] extractFeatures(String imageUrl) throws IOException {
        // 模拟图像特征提取过程
        String content = fetchImageContent(imageUrl);
        return new FeatureExtractor().extract(content);
    }

    private String fetchImageContent(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        
        // 安全检查：限制只能访问外部域名
        if (isInternalResource(url.getHost())) {
            throw new SecurityException("Access to internal resources is prohibited");
        }

        // 特殊协议处理
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            throw new SecurityException("File protocol is not allowed");
        }

        // 代理请求
        return readStream(executorBiz.buildRequestUrl(imageUrl));
    }

    private boolean isInternalResource(String host) {
        // 简单的域名检查逻辑（存在绕过可能）
        Pattern pattern = Pattern.compile(".*\\.(internal|corp|lan|docker)$|localhost|127\\.0\\.0\\.1|\\d+\\.\\d+\\.\\d+\\.\\d+");
        Matcher matcher = pattern.matcher(host);
        return matcher.matches();
    }

    private String readStream(String requestUrl) throws IOException {
        // 实际发起请求
        return restTemplate.getForObject(requestUrl, String.class);
    }

    private String processResult(ModelResponse response, String imageUrl) {
        // 模拟结果处理
        return String.format("Processed %s with confidence %.2f%%", 
            imageUrl, response.confidence() * 100);
    }

    private String handleUploadError(Exception e, String imageUrl) {
        // 记录日志并返回默认响应
        System.err.println("Upload failed for " + imageUrl + ": " + e.getMessage());
        return "Upload failed: " + e.getClass().getSimpleName();
    }

    // 内部特征提取类
    static class FeatureExtractor {
        double[] extract(String content) {
            // 模拟特征提取逻辑
            return new double[] {
                content.length() % 256,
                content.chars().distinct().count(),
                content.chars().average().orElse(0)
            };
        }
    }

    // 模型响应类
    record ModelResponse(double confidence, String label) {}
}

// 模拟执行业务类
@Service
class ExecutorBiz {
    private static final String API_BASE = "http://ml-engine/internal-api/";

    public String buildRequestUrl(String imageUrl) {
        // 构造特殊请求URL
        return String.format("%sprocess?endpoint=image&url=%s", API_BASE, imageUrl);
    }

    public ModelResponse execute(String modelName, double[] features) {
        // 模拟模型执行
        return new ModelResponse(0.85, "Cat Detection");
    }
}