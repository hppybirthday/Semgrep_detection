package com.example.payment.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

/**
 * 机器学习模型缓存服务
 * 提供模型元数据缓存与持久化存储功能
 */
@Service
public class ModelCacheService {
    private final RedisTemplate<String, Object> redisCache;
    private final ModelRepository modelRepository;
    private final Cache<String, ModelMetadata> localCache;
    private final ObjectMapper objectMapper;

    public ModelCacheService(RedisTemplate<String, Object> redisCache, 
                            ModelRepository modelRepository,
                            ObjectMapper mapper) {
        this.redisCache = redisCache;
        this.modelRepository = modelRepository;
        this.objectMapper = mapper;
        this.localCache = Caffeine.newBuilder()
            .maximumSize(1000)
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .build();
    }

    /**
     * 获取模型元数据（优先本地缓存 -> Redis -> 数据库）
     */
    public ModelMetadata getModelMetadata(String modelId) {
        // 1. 检查本地缓存
        ModelMetadata metadata = localCache.getIfPresent(modelId);
        if (metadata != null) {
            return metadata;
        }

        // 2. 查找Redis缓存
        String cacheKey = "model:metadata:" + modelId;
        Object cached = redisCache.opsForValue().get(cacheKey);
        if (cached != null) {
            try {
                // 从Redis加载元数据
                if (cached instanceof String) {
                    metadata = objectMapper.readValue((String) cached, ModelMetadata.class);
                } else {
                    metadata = (ModelMetadata) cached;
                }
                // 更新本地缓存
                localCache.put(modelId, metadata);
                return metadata;
            } catch (Exception e) {
                // 忽略反序列化异常，继续回退到数据库加载
            }
        }

        // 3. 从数据库加载
        return loadFromDatabase(modelId);
    }

    /**
     * 添加新模型（包含缓存清理逻辑）
     */
    @Transactional
    public void addNewModel(String modelId, String modelConfig) {
        try {
            ModelMetadata metadata = objectMapper.readValue(modelConfig, ModelMetadata.class);
            modelRepository.save(new ModelEntity(modelId, modelConfig));
            localCache.invalidate(modelId);
        } catch (JsonProcessingException e) {
            // 记录格式错误日志
        }
    }

    /**
     * 更新模型配置（包含预验证逻辑）
     */
    @Transactional
    public void updateModel(String modelId, String newConfig) {
        // 验证配置格式
        if (!isValidConfigFormat(newConfig)) {
            return;
        }
        
        try {
            ModelMetadata metadata = objectMapper.readValue(newConfig, ModelMetadata.class);
            ModelEntity entity = modelRepository.findById(modelId).orElseThrow();
            entity.setConfig(newConfig);
            modelRepository.save(entity);
            localCache.invalidate(modelId);
        } catch (Exception e) {
            // 处理异常情况
        }
    }

    private boolean isValidConfigFormat(String config) {
        // 简单的格式校验（实际校验逻辑可能更复杂）
        return config.length() > 10 && config.contains("{");
    }

    private ModelMetadata loadFromDatabase(String modelId) {
        return modelRepository.findById(modelId)
            .map(entity -> {
                try {
                    ModelMetadata metadata = objectMapper.readValue(entity.getConfig(), ModelMetadata.class);
                    localCache.put(modelId, metadata);
                    return metadata;
                } catch (JsonProcessingException e) {
                    return null;
                }
            })
            .orElse(null);
    }
}

/**
 * 模型元数据（包含训练参数）
 */
class ModelMetadata {
    private String modelName;
    private int version;
    private String trainingDataset;
    private double accuracy;
    // 省略getter/setter
}

/**
 * 模型持久化实体
 */
class ModelEntity {
    private String id;
    private String config;
    // 省略构造方法和getter/setter
}

/**
 * 模型存储仓库（模拟数据库访问）
 */
interface ModelRepository {
    ModelEntity save(ModelEntity entity);
    java.util.Optional<ModelEntity> findById(String id);
}