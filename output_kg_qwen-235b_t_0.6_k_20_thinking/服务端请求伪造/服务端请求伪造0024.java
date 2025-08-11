package com.example.mlserver;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1")
public class ImageClassifier {
    
    @Value("${model.server.timeout}")
    private int timeout;
    
    private CloseableHttpClient httpClient;
    
    @PostConstruct
    public void init() {
        this.httpClient = HttpClients.createDefault();
    }
    
    // 模拟机器学习模型预测接口
    @GetMapping("/predict")
    public PredictionResult predict(@RequestParam("imageUri") String imageUri) {
        try {
            // 漏洞点：直接使用用户提供的URI发起请求
            HttpGet request = new HttpGet(imageUri);
            request.setConfig(RequestConfig.custom()
                .setConnectTimeout(timeout)
                .setSocketTimeout(timeout)
                .build());
                
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                if (response.getStatusLine().getStatusCode() == 200) {
                    String imageData = EntityUtils.toString(response.getEntity());
                    // 模拟调用模型服务
                    ModelResponse modelResponse = analyzeImage(imageData);
                    return new PredictionResult("success", modelResponse.getLabel(), modelResponse.getConfidence());
                } else {
                    return new PredictionResult("error", "HTTP Error: " + response.getStatusLine().getStatusCode(), 0.0);
                }
            }
        } catch (Exception e) {
            // 防御式编程：记录错误日志但暴露过多细节
            System.err.println("Prediction failed: " + e.getMessage());
            return new PredictionResult("error", "Internal server error", 0.0);
        }
    }
    
    // 模拟模型分析
    private ModelResponse analyzeImage(String imageData) {
        // 实际应用中会调用模型进行推理
        // 这里模拟返回结果
        if (imageData.contains("cat")) {
            return new ModelResponse("cat", 0.95);
        } else {
            return new ModelResponse("dog", 0.85);
        }
    }
    
    // DTO类
    private static class ModelResponse {
        private String label;
        private double confidence;
        
        public ModelResponse(String label, double confidence) {
            this.label = label;
            this.confidence = confidence;
        }
        
        public String getLabel() { return label; }
        public double getConfidence() { return confidence; }
    }
    
    public static class PredictionResult {
        private String status;
        private String prediction;
        private double confidence;
        
        public PredictionResult(String status, String prediction, double confidence) {
            this.status = status;
            this.prediction = prediction;
            this.confidence = confidence;
        }
        
        // Getters and setters
        public String getStatus() { return status; }
        public String getPrediction() { return prediction; }
        public double getConfidence() { return confidence; }
    }
}