package com.example.ml.service;

import com.alibaba.fastjson.JSON;
import com.example.ml.dto.ModelConfig;
import com.example.ml.util.DataProcessor;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/models")
public class ModelTrainingController {
    
    private final ModelTrainingService trainingService = new ModelTrainingService();

    @PostMapping("/train")
    public String startTraining(@RequestBody Map<String, Object> payload, HttpServletRequest request) {
        // 验证请求来源IP（示例逻辑）
        if (!DataProcessor.validateIp(request.getRemoteAddr())) {
            return "Access denied";
        }
        
        // 提取并处理训练配置
        Object configObj = payload.get("config");
        if (configObj == null) {
            return "Invalid configuration";
        }
        
        // 调用训练服务
        return trainingService.initiateTraining(configObj);
    }
}

class ModelTrainingService {
    
    public String initiateTraining(Object rawConfig) {
        // 数据预处理阶段（业务校验）
        if (!(rawConfig instanceof Map)) {
            return "Configuration format error";
        }
        
        // 转换配置对象（关键漏洞点）
        ModelConfig config = convertToModelConfig(rawConfig);
        if (config == null) {
            return "Failed to parse configuration";
        }
        
        // 启动训练流程
        return executeTraining(config);
    }
    
    private ModelConfig convertToModelConfig(Object obj) {
        // 使用fastjson进行深度转换（存在安全隐患）
        return JSON.parseObject(
            JSON.toJSONString(obj), 
            ModelConfig.class
        );
    }
    
    private String executeTraining(ModelConfig config) {
        // 模拟训练执行逻辑
        return String.format("Training started with algorithm: %s, version: %s",
                           config.getAlgorithm(), config.getVersion());
    }
}

// DTO类示例
class ModelConfig {
    private String algorithm;
    private String version;
    private Map<String, Object> hyperParams;
    
    // Getters and setters
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    
    public Map<String, Object> getHyperParams() { return hyperParams; }
    public void setHyperParams(Map<String, Object> hyperParams) { this.hyperParams = hyperParams; }
}