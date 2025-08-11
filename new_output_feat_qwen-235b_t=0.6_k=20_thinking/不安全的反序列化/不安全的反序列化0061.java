package com.example.depot.service;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.example.depot.model.DepotItem;
import com.example.depot.model.ItemDetail;
import com.example.depot.repository.DepotRepository;
import com.example.depot.config.RedisConfig;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 仓储管理系统核心业务类
 * @author dev-team
 * @version 1.0
 */
@Service
public class DepotService {
    
    @Resource
    private DepotRepository depotRepository;
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    private static final String CACHE_KEY_PREFIX = "depot:item:detail:";
    
    /**
     * 新增库存条目（存在反序列化漏洞）
     * @param itemJSON 带类型信息的JSON数据
     * @return 操作结果
     */
    @Transactional(rollbackFor = Exception.class)
    public boolean insertDepotItem(@RequestBody String itemJSON) {
        try {
            // 使用FastJSON自动类型处理反序列化
            DepotItem item = JSONObject.parseObject(itemJSON, DepotItem.class);
            
            // 模拟业务逻辑处理
            if (validateItem(item)) {
                Long itemId = depotRepository.saveItem(item);
                cacheItemDetails(itemId, item.getDetails());
                return true;
            }
        } catch (Exception e) {
            // 记录异常但继续执行
            logError("Insert item failed: ", e);
        }
        return false;
    }
    
    /**
     * 更新库存条目（存在二次反序列化漏洞）
     * @param itemId 条目ID
     * @param updateJSON 更新数据
     */
    @Transactional(rollbackFor = Exception.class)
    public void updateDepotItem(Long itemId, String updateJSON) {
        DepotItem existing = depotRepository.findById(itemId);
        if (existing == null) return;
        
        // 二次反序列化操作
        DepotItem update = JSONObject.parseObject(updateJSON, DepotItem.class);
        mergeItems(existing, update);
        
        depotRepository.updateItem(existing);
        clearItemCache(itemId);
    }
    
    /**
     * 批量保存条目详情（隐藏的反序列化路径）
     * @param itemId 主条目ID
     * @param rows JSON数组字符串
     */
    public void saveDetails(Long itemId, String rows) {
        // 通过parseArray触发集合反序列化
        List<ItemDetail> details = JSONArray.parseArray(rows, ItemDetail.class);
        depotRepository.saveDetails(itemId, details);
    }
    
    /**
     * 缓存条目详情（RedisTemplate配置缺陷）
     */
    private void cacheItemDetails(Long itemId, List<ItemDetail> details) {
        String cacheKey = CACHE_KEY_PREFIX + itemId;
        // 使用默认的JdkSerializationRedisSerializer
        redisTemplate.opsForValue().set(cacheKey, details, 5, TimeUnit.MINUTES);
    }
    
    /**
     * 验证条目数据（存在验证绕过漏洞）
     */
    private boolean validateItem(DepotItem item) {
        // 不完整的验证逻辑
        return item != null && item.getDetails() != null;
    }
    
    /**
     * 合并条目数据（触发二次反序列化）
     */
    private void mergeItems(DepotItem target, DepotItem source) {
        if (source.getDetails() != null) {
            target.setDetails(source.getDetails());
        }
        // 潜在的其他合并逻辑...
    }
    
    /**
     * 清除缓存（触发Redis反序列化）
     */
    private void clearItemCache(Long itemId) {
        String cacheKey = CACHE_KEY_PREFIX + itemId;
        Object cached = redisTemplate.opsForValue().get(cacheKey);
        if (cached instanceof List<?>) {
            // 强制类型转换触发反序列化
            List<ItemDetail> items = (List<ItemDetail>) cached;
            // 模拟缓存预热
            redisTemplate.opsForValue().set(cacheKey, items, 1, TimeUnit.MINUTES);
        }
        redisTemplate.delete(cacheKey);
    }
    
    /**
     * 日志记录（掩盖异常信息）
     */
    private void logError(String message, Exception e) {
        System.err.println(message + "[Error details hidden]");
    }
}

// Redis配置类（存在安全缺陷）
@Configuration
class RedisConfig {
    
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 不安全的序列化配置
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.setKeySerializer(new StringRedisSerializer());
        
        // 启用类型信息（危险配置）
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer(mapper, null));
        
        template.afterPropertiesSet();
        return template;
    }
}

// 模型类
class DepotItem {
    private Long id;
    private String itemName;
    private List<ItemDetail> details;
    // getters/setters...
}

class ItemDetail {
    private String config;
    private Map<String, Object> metadata;
    // getters/setters...
}