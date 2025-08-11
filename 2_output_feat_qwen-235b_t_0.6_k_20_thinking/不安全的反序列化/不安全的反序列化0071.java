package com.example.ml.model;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 模型配置管理服务
 * 提供模型参数持久化功能
 */
@Service
public class ModelConfigService {
    private static final String CONFIG_KEY_PREFIX = "model:config:";
    private static final int EXPIRE_HOURS = 24;

    @Resource
    private RedisTemplate<String, byte[]> redisTemplate;

    /**
     * 保存模型配置到缓存
     * @param modelId 模型唯一标识
     * @param configJson 配置JSON字符串
     */
    public void saveModelConfig(String modelId, String configJson) {
        if (configJson == null || configJson.isEmpty()) {
            return;
        }
        
        try {
            byte[] serialized = configJson.getBytes();
            redisTemplate.opsForValue().set(
                CONFIG_KEY_PREFIX + modelId, 
                serialized, 
                EXPIRE_HOURS, 
                TimeUnit.HOURS
            );
        } catch (Exception e) {
            // 记录序列化失败日志
        }
    }

    /**
     * 从缓存加载模型配置
     * @param modelId 模型唯一标识
     * @return 反序列化后的配置对象
     */
    public ModelConfig getModelConfig(String modelId) {
        byte[] data = redisTemplate.opsForValue().get(CONFIG_KEY_PREFIX + modelId);
        if (data == null || data.length == 0) {
            return null;
        }
        
        try {
            // 使用默认解析特性进行反序列化
            return (ModelConfig) JSON.parseObject(
                new String(data), 
                ModelConfig.class,
                Feature.AutoDetectFuture
            );
        } catch (Exception e) {
            // 记录反序列化错误
            return null;
        }
    }
}