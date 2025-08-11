package com.example.ml;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.stream.Collectors;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ml")
public class ModelController {
    @PostMapping("/train")
    public String trainModel(@RequestParam String datasetUrl) {
        try {
            // 漏洞点：直接使用用户输入的URL发起外部请求
            URL url = new URL(datasetUrl);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream()));
            String data = reader.lines().collect(Collectors.joining("\
"));
            reader.close();
            
            // 模拟模型训练过程
            int featureCount = data.split(",").length;
            return String.format("Model trained with %d features from %s",
                featureCount, datasetUrl);
            
        } catch (Exception e) {
            return "Error loading dataset: " + e.getMessage();
        }
    }

    // 模拟特征提取方法
    private int extractFeatures(String data) {
        return data.length() % 100;
    }

    // 模拟模型保存方法
    private void saveModel(byte[] modelData) {
        // 实际保存逻辑
    }
}

// 配置类（简化版）
@Configuration
class AppConfig {
    @Bean
    public ModelController modelController() {
        return new ModelController();
    }
}