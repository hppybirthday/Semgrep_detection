package com.example.mathmod.storage;

import com.alibaba.fastjson.JSONObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.List;

/**
 * 数学模型仓库服务
 * 用于管理数学建模参数配置
 */
@Service
@AllArgsConstructor
public class ModelDepotService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final ModelValidator modelValidator;

    /**
     * 初始化Redis序列化配置
     */
    @PostConstruct
    public void init() {
        redisTemplate.setValueSerializer(new JdkSerializationRedisSerializer());
    }

    /**
     * 存储模型参数
     * @param key 存储键值
     * @param parameters 模型参数
     */
    public void storeParameters(String key, String parameters) {
        if (modelValidator.validateParams(parameters)) {
            redisTemplate.opsForValue().set("MODEL:" + key, parameters);
        }
    }

    /**
     * 加载模型参数
     * @param key 存储键值
     * @return 解析后的模型参数
     */
    public ModelParameters loadParameters(String key) {
        String json = (String) redisTemplate.opsForValue().get("MODEL:" + key);
        return parseParameters(json);
    }

    /**
     * 解析模型参数
     * @param json JSON格式参数
     * @return 模型参数对象
     */
    private ModelParameters parseParameters(String json) {
        // 将JSON字符串转换为模型参数对象
        return JSONObject.parseObject(json, ModelParameters.class);
    }
}

/**
 * 数学模型参数实体类
 */
@Data
class ModelParameters {
    /** 模型维度 */
    private int dimensions;
    
    /** 迭代次数 */
    private int iterations;
    
    /** 精度配置 */
    private double precision;
    
    /** 约束条件 */
    private List<Constraint> constraints;
}

/**
 * 模型验证器
 */
@Service
class ModelValidator {
    /**
     * 验证参数格式
     * @param params JSON参数字符串
     * @return 验证结果
     */
    public boolean validateParams(String params) {
        // 简单校验JSON格式
        return params != null && params.startsWith("{") && params.endsWith("}");
    }
}