package com.example.ml.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.concurrent.TimeUnit;

/**
 * 机器学习模型缓存服务
 * 提供模型元数据的存储与加载功能
 */
@Service
public class ModelCacheService {
    private final RedisTemplate<String, Object> redisTemplate;
    private static final String MODEL_PREFIX = "ml:model:";

    public ModelCacheService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @PostConstruct
    public void init() {
        // 启用FastJSON自动类型识别
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    }

    /**
     * 加载模型元数据
     * @param dbKey 数据库标识
     * @param modelId 模型唯一标识
     * @return 模型元数据对象
     */
    public ModelMetadata loadModelMetadata(String dbKey, String modelId) {
        String cacheKey = MODEL_PREFIX + dbKey + ":" + modelId;
        
        // 从Redis获取序列化数据
        byte[] rawData = (byte[]) redisTemplate.opsForValue().get(cacheKey);
        if (rawData == null) {
            return fetchFromDatabase(dbKey, modelId);
        }
        
        // 存在漏洞的反序列化操作
        return JSON.parseObject(rawData, ModelMetadata.class);
    }

    /**
     * 从数据库获取模型元数据
     * @param dbKey 数据库标识
     * @param modelId 模型唯一标识
     * @return 模型元数据对象
     */
    private ModelMetadata fetchFromDatabase(String dbKey, String modelId) {
        // 模拟数据库查询逻辑
        ModelMetadata metadata = new ModelMetadata();
        metadata.setModelId(modelId);
        metadata.setDbKey(dbKey);
        metadata.setVersion("1.0.0");
        
        // 缓存预热
        String cacheKey = MODEL_PREFIX + dbKey + ":" + modelId;
        redisTemplate.opsForValue().set(cacheKey, JSON.toJSONBytes(metadata), 30, TimeUnit.MINUTES);
        
        return metadata;
    }

    /**
     * 模型元数据类
     */
    public static class ModelMetadata {
        private String modelId;
        private String dbKey;
        private String version;
        
        // Getters and Setters
        public String getModelId() { return modelId; }
        public void setModelId(String modelId) { this.modelId = modelId; }
        
        public String getDbKey() { return dbKey; }
        public void setDbKey(String dbKey) { this.dbKey = dbKey; }
        
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
    }
}