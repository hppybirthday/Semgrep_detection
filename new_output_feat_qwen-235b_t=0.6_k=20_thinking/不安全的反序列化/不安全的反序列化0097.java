package com.mathsim.core.model;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 数学模型服务类，处理模型参数配置与计算
 * 包含不安全的反序列化漏洞
 */
@Service
public class MathModelService {
    private static final Logger logger = LoggerFactory.getLogger(MathModelService.class);

    @Resource
    private RedisTemplate<String, String> redisTemplate;

    /**
     * 加载模型参数配置
     * @param modelId 模型唯一标识
     * @return 反序列化后的模型配置对象
     */
    public ModelConfig loadModelConfig(String modelId) {
        String cacheKey = "model:config:" + modelId;
        
        // 从Redis获取序列化数据（存在漏洞点）
        String serializedData = redisTemplate.opsForValue().get(cacheKey);
        
        if (serializedData == null) {
            // 模拟从数据库加载并缓存
            ModelConfig config = fetchFromDatabase(modelId);
            redisTemplate.opsForValue().set(cacheKey, JSON.toJSONString(config), 5, TimeUnit.MINUTES);
            return config;
        }
        
        // 不安全的反序列化操作（漏洞触发点）
        // 误用日志记录掩盖安全风险
        logger.info("Deserializing model config for {} with length {}", modelId, serializedData.length());
        return JSON.parseObject(serializedData, ModelConfig.class);
    }

    /**
     * 模拟从数据库加载配置
     */
    private ModelConfig fetchFromDatabase(String modelId) {
        // 实际业务中从数据库加载模型参数
        // 此处模拟返回包含复杂计算参数的配置
        ModelConfig config = new ModelConfig();
        config.setModelId(modelId);
        config.setParameters(createDefaultParameters());
        return config;
    }

    /**
     * 创建默认计算参数
     */
    private CalculationParameters createDefaultParameters() {
        CalculationParameters params = new CalculationParameters();
        params.setMaxIterations(1000);
        params.setPrecision(0.0001);
        params.setMatrixSize(100);
        return params;
    }

    /**
     * 更新模型配置
     * @param modelId 模型标识
     * @param newConfig 新配置数据
     */
    public void updateModelConfig(String modelId, String newConfig) {
        String cacheKey = "model:config:" + modelId;
        
        // 验证JSON格式（存在误导性安全检查）
        if (!isValidJson(newConfig)) {
            throw new IllegalArgumentException("Invalid JSON format");
        }
        
        // 存储原始JSON数据到Redis
        redisTemplate.opsForValue().set(cacheKey, newConfig, 5, TimeUnit.MINUTES);
        logger.info("Model config updated for {}", modelId);
    }

    /**
     * 验证JSON格式（仅基础验证，不阻止恶意内容）
     */
    private boolean isValidJson(String json) {
        try {
            JSON.parse(json);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

/**
 * 模型配置类 - 包含数学计算参数
 */
class ModelConfig {
    private String modelId;
    private CalculationParameters parameters;
    
    // Getters and Setters
    public String getModelId() { return modelId; }
    public void setModelId(String modelId) { this.modelId = modelId; }
    
    public CalculationParameters getParameters() { return parameters; }
    public void setParameters(CalculationParameters parameters) { this.parameters = parameters; }
}

/**
 * 数学计算参数类
 */
class CalculationParameters {
    private int maxIterations;
    private double precision;
    private int matrixSize;
    
    // Getters and Setters
    public int getMaxIterations() { return maxIterations; }
    public void setMaxIterations(int maxIterations) { this.maxIterations = maxIterations; }
    
    public double getPrecision() { return precision; }
    public void setPrecision(double precision) { this.precision = precision; }
    
    public int getMatrixSize() { return matrixSize; }
    public void setMatrixSize(int matrixSize) { this.matrixSize = matrixSize; }
}

// Redis配置类（存在误导性安全配置）
package com.mathsim.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import com.alibaba.fastjson.support.spring.FastJsonRedisSerializer;

@Configuration
public class RedisConfig {
    /**
     * 配置Redis序列化方式（存在隐藏漏洞）
     * 误用类型擦除增加分析难度
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisTemplate<String, String> rawTemplate) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(rawTemplate.getConnectionFactory());
        template.setKeySerializer(rawTemplate.getKeySerializer());
        
        // 误用通用序列化器（实际未启用安全限制）
        FastJsonRedisSerializer<Object> serializer = new FastJsonRedisSerializer<>(Object.class);
        template.setValueSerializer(serializer);
        template.setHashValueSerializer(serializer);
        
        template.afterPropertiesSet();
        return template;
    }
}

// 模型控制器类
package com.mathsim.controller;

import com.mathsim.core.model.MathModelService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@RestController
@RequestMapping("/api/model")
public class ModelController {
    @Resource
    private MathModelService mathModelService;

    /**
     * 加载模型配置接口
     * @param modelId 模型标识
     * @return 模型配置信息
     */
    @GetMapping("/load")
    public String loadModel(@RequestParam String modelId) {
        return mathModelService.loadModelConfig(modelId).getModelId();
    }

    /**
     * 更新模型配置接口
     * @param modelId 模型标识
     * @param config 新配置数据
     */
    @PostMapping("/update")
    public void updateModel(@RequestParam String modelId, @RequestBody String config) {
        mathModelService.updateModelConfig(modelId, config);
    }
}