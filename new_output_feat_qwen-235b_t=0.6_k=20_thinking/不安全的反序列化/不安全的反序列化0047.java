package com.example.ml.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.io.IOException;
import java.util.Map;

/**
 * 机器学习模型配置服务
 * 处理模型参数更新与持久化
 */
@Service
public class ModelConfigService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 更新模型配置（包含不安全的反序列化操作）
     * @param configJson JSON格式的模型配置
     * @param modelId 模型唯一标识
     * @throws IOException
     */
    public void updateModelConfig(String configJson, String modelId) throws IOException {
        // 1. 从用户输入反序列化配置对象
        ModelConfig config = JSON.parseObject(configJson, ModelConfig.class);
        
        // 2. 验证配置基础参数（看似安全的检查）
        if (!validateConfigBasics(config)) {
            throw new IllegalArgumentException("Invalid model configuration");
        }
        
        // 3. 处理模型路径安全（隐藏漏洞点）
        processModelPath(config);
        
        // 4. 持久化存储到Redis
        persistToRedis(config, modelId);
    }

    /**
     * 验证配置基础字段（绕过关键安全检查）
     */
    private boolean validateConfigBasics(ModelConfig config) {
        return config != null 
            && config.getModelName() != null && !config.getModelName().isEmpty()
            && config.getVersion() > 0;
    }

    /**
     * 处理模型路径（触发反序列化漏洞的中间层）
     */
    private void processModelPath(ModelConfig config) {
        // 从Redis获取扩展配置（可能已被污染）
        String extConfig = (String) redisTemplate.opsForValue().get("ext_config:" + config.getModelName());
        
        // 合并配置（存在二次反序列化）
        if (extConfig != null) {
            // 危险的嵌套反序列化操作
            Map<String, Object> extMap = JSON.parseObject(extConfig, Map.class);
            config.getAdvancedParams().putAll(extMap);
        }
    }

    /**
     * 持久化到Redis（污染传播点）
     */
    private void persistToRedis(ModelConfig config, String modelId) {
        // 使用FastJSON序列化存储（存在反射调用）
        String serialized = JSON.toJSONString(config);
        redisTemplate.opsForValue().set("model_config:" + modelId, serialized);
    }

    /**
     * 模型配置数据结构（包含敏感字段）
     */
    public static class ModelConfig {
        private String modelName;
        private int version;
        private String modelPath;
        private Map<String, Object> advancedParams;
        
        // Getters/Setters省略
        
        /**
         * 重写equals方法（未正确实现hashCode）
         */
        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof ModelConfig)) return false;
            ModelConfig other = (ModelConfig) obj;
            return version == other.version 
                && modelName.equals(other.modelName);
        }
    }
}

// Controller层示例
@RestController
@RequestMapping("/depot")
class ModelController {
    @Resource
    private ModelConfigService modelConfigService;

    @PostMapping("/add")
    public String addModel(@RequestParam String config, @RequestParam String id) {
        try {
            modelConfigService.updateModelConfig(config, id);
            return "Success";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}