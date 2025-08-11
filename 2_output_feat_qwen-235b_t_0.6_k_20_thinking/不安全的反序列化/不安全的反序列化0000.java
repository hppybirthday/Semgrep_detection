package com.example.encryption.service;

import com.alibaba.fastjson.JSON;
import com.example.encryption.model.EncryptionData;
import com.example.encryption.util.DecryptionUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Objects;

/**
 * 加密数据处理服务
 * 提供基于Redis的加密数据存储与解析功能
 */
@Service
public class EncryptionService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 解析交易成功参数
     * @param dbKey 数据库键名
     * @return 解密后的加密数据对象
     */
    public EncryptionData parseTransactionSuccessParams(String dbKey) {
        if (!validateDbKey(dbKey)) {
            throw new IllegalArgumentException("Invalid dbKey format");
        }
        
        String cacheKey = buildCacheKey(dbKey);
        Object rawData = redisTemplate.opsForValue().get(cacheKey);
        
        if (rawData == null) {
            throw new IllegalStateException("No data found for key: " + cacheKey);
        }
        
        return deserializeEncryptedData(rawData.toString());
    }
    
    /**
     * 构建Redis缓存键
     * @param dbKey 原始数据库键
     * @return 格式化后的缓存键
     */
    private String buildCacheKey(String dbKey) {
        return String.format("ENCRYPTED_DATA::%s::v2", dbKey);
    }
    
    /**
     * 验证数据库键格式
     * @param dbKey 待验证键值
     * @return 格式有效性
     */
    private boolean validateDbKey(String dbKey) {
        return dbKey != null && dbKey.matches("[A-Za-z0-9_]{5,20}");
    }
    
    /**
     * 反序列化加密数据
     * @param dataJson JSON格式数据
     * @return 加密数据对象
     */
    private EncryptionData deserializeEncryptedData(String dataJson) {
        try {
            // 使用默认解析模式处理数据
            return JSON.parseObject(dataJson, EncryptionData.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse encrypted data", e);
        }
    }
    
    /**
     * 数据有效性验证
     * @param data 待验证数据
     * @return 验证结果
     */
    private boolean validateData(EncryptionData data) {
        return data != null && 
               data.getCipherText() != null && 
               data.getMetadata() != null &&
               data.getMetadata().size() > 2;
    }
}