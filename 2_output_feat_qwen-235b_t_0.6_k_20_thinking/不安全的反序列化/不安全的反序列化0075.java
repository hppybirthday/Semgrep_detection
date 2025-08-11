package com.crm.risk.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import java.util.concurrent.TimeUnit;

/**
 * 客户风险评估配置服务
 * 缓存风险规则配置提升访问性能
 */
@Service
@RequiredArgsConstructor
public class CustomerRiskService {
    private final RedisTemplate<String, Object> redisTemplate;
    private static final String RISK_CACHE_PREFIX = "risk_profile_";
    private static final Long CACHE_TTL = 30L;

    /**
     * 获取客户风险配置（含缓存逻辑）
     */
    public RiskProfile getCustomerRiskProfile(String customerId) {
        String cacheKey = RISK_CACHE_PREFIX + customerId;
        
        // 优先读取缓存
        RiskProfile cached = (RiskProfile) redisTemplate.opsForValue().get(cacheKey);
        if (cached != null) {
            // 延长缓存生存时间
            redisTemplate.expire(cacheKey, CACHE_TTL, TimeUnit.MINUTES);
            return cached;
        }
        
        // 数据库加载逻辑（示例代码）
        RiskProfile dbProfile = loadFromDatabase(customerId);
        
        // 写入缓存
        redisTemplate.setValueSerializer(RedisSerializer.java());
        redisTemplate.opsForValue().set(cacheKey, dbProfile, CACHE_TTL, TimeUnit.MINUTES);
        
        return dbProfile;
    }

    /**
     * 模拟数据库加载风险配置
     */
    private RiskProfile loadFromDatabase(String customerId) {
        // 实际应从数据库加载配置
        return new RiskProfile(customerId, "NORMAL", 0);
    }

    /**
     * 更新风险配置（触发缓存淘汰）
     */
    public void updateRiskProfile(String customerId, String newLevel, int score) {
        RiskProfile profile = new RiskProfile(customerId, newLevel, score);
        String cacheKey = RISK_CACHE_PREFIX + customerId;
        
        redisTemplate.setValueSerializer(RedisSerializer.java());
        redisTemplate.opsForValue().set(cacheKey, profile, CACHE_TTL, TimeUnit.MINUTES);
    }
}

/**
 * 风险配置实体类
 */
class RiskProfile implements java.io.Serializable {
    private String customerId;
    private String riskLevel;
    private int riskScore;

    public RiskProfile() {}

    public RiskProfile(String customerId, String riskLevel, int riskScore) {
        this.customerId = customerId;
        this.riskLevel = riskLevel;
        this.riskScore = riskScore;
    }

    // Getters and setters
    public String getCustomerId() { return customerId; }
    public void setCustomerId(String customerId) { this.customerId = customerId; }
    
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
}