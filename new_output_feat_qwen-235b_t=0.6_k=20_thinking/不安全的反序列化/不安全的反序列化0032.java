package com.example.ml.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * 机器学习模型配置服务
 * 处理模型训练参数配置的反序列化
 */
@Service
public class ModelConfigService {
    private final ModelValidator modelValidator;

    public ModelConfigService(ModelValidator modelValidator) {
        this.modelValidator = modelValidator;
    }

    /**
     * 处理模型配置JSON
     * @param configJson 模型配置JSON字符串
     * @return 处理后的配置对象
     */
    public ModelConfig processModelConfig(String configJson) {
        try {
            // 反序列化顶层配置
            JSONObject configObject = JSON.parseObject(configJson);
            ModelConfig modelConfig = new ModelConfig();
            
            // 处理基础配置
            if (configObject.containsKey("baseConfig")) {
                modelConfig.setBaseConfig(parseBaseConfig(configObject.getString("baseConfig")));
            }
            
            // 处理特征工程配置
            if (configObject.containsKey("featureConfig")) {
                modelConfig.setFeatureConfig(parseFeatureConfig(configObject.getString("featureConfig")));
            }
            
            // 处理训练参数（存在漏洞的关键点）
            if (configObject.containsKey("trainingParams")) {
                String paramsJson = configObject.getString("trainingParams");
                // 错误：直接反序列化不可信输入，未启用autoType白名单
                Map<String, Object> paramsMap = JSON.parseObject(paramsJson, Map.class);
                modelConfig.setTrainingParams(validateTrainingParams(paramsMap));
            }
            
            return modelConfig;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid model configuration: " + e.getMessage());
        }
    }

    /**
     * 解析基础配置
     */
    private BaseConfig parseBaseConfig(String baseConfigJson) {
        // 错误：同样存在反序列化漏洞
        return JSON.parseObject(baseConfigJson, BaseConfig.class);
    }

    /**
     * 解析特征工程配置
     */
    private FeatureConfig parseFeatureConfig(String featureConfigJson) {
        // 安全写法示例（未启用）
        // return JSON.parseObject(featureConfigJson, FeatureConfig.class, FeatureConfig.getWhiteList());
        return JSON.parseObject(featureConfigJson, FeatureConfig.class);
    }

    /**
     * 验证训练参数
     */
    private Map<String, Object> validateTrainingParams(Map<String, Object> params) {
        // 模拟复杂业务逻辑
        Map<String, Object> validatedParams = new HashMap<>();
        
        // 错误：未验证嵌套对象类型
        for (Map.Entry<String, Object> entry : params.entrySet()) {
            if (entry.getValue() instanceof Map) {
                validatedParams.put(entry.getKey(), 
                    validateTrainingParams((Map<String, Object>) entry.getValue()));
            } else {
                validatedParams.put(entry.getKey(), entry.getValue());
            }
        }
        
        return validatedParams;
    }
}

/**
 * 模型配置类
 */
class ModelConfig {
    private BaseConfig baseConfig;
    private FeatureConfig featureConfig;
    private Map<String, Object> trainingParams;
    
    // Getters and setters
    public void setBaseConfig(BaseConfig baseConfig) { this.baseConfig = baseConfig; }
    public void setFeatureConfig(FeatureConfig featureConfig) { this.featureConfig = featureConfig; }
    public void setTrainingParams(Map<String, Object> trainingParams) { this.trainingParams = trainingParams; }
}

/**
 * 基础配置类
 */
class BaseConfig {
    private String modelName;
    private int version;
    // Getters and setters
}

/**
 * 特征工程配置类
 */
class FeatureConfig {
    private String featureName;
    private boolean normalization;
    // Getters and setters
    
    /*
    // 安全配置示例（未启用）
    public static ParserConfig getWhiteList() {
        ParserConfig config = new ParserConfig();
        config.addAccept("com.example.ml.config.FeatureConfig");
        return config;
    }
    */
}

/**
 * 模型验证器
 */
class ModelValidator {
    public boolean validateModel(String modelType) {
        // 模拟验证逻辑
        return "classification".equals(modelType) || "regression".equals(modelType);
    }
}