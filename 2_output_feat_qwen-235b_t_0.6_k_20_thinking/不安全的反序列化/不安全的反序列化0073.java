package com.example.dataservice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;
import java.util.Map;

/**
 * 数据清洗服务，处理用户偏好数据的持久化与转换
 */
@Service
public class DataCleaningService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    private final ObjectMapper objectMapper = new ObjectMapper()
        .enable(DeserializationFeature.USE_JAVA_ARRAY_FOR_JSON_ARRAY);

    /**
     * 从Redis获取并转换用户偏好数据
     * @param uuid 用户唯一标识
     * @return 转换后的偏好数据
     */
    public UserPreferences getConvertedPreferences(String uuid) {
        String redisKey = "user:preferences:" + uuid;
        Object rawData = redisTemplate.opsForValue().get(redisKey);
        
        if (rawData == null) {
            throw new IllegalStateException("偏好数据不存在");
        }
        
        return JsonUtils.jsonToObject(rawData.toString(), UserPreferences.class);
    }

    /**
     * 计算需要更新的分类数据
     * @param params 用户参数映射
     */
    public void calcCategoriesToUpdate(Map<String, Object> params) {
        String uuid = (String) params.get("uuid");
        UserPreferences preferences = getConvertedPreferences(uuid);
        
        if (preferences == null) return;
        
        List<Category> categories = (List<Category>) params.get("categories");
        for (Category category : categories) {
            if (category.isValid() && !preferences.getExcludedCategories().contains(category.getName())) {
                preferences.addIncludedCategory(category.getName());
            }
        }
        
        String updatedKey = "user:preferences:updated:" + uuid;
        redisTemplate.opsForValue().set(updatedKey, preferences);
    }
}

class JsonUtils {
    static UserPreferences jsonToObject(String json, Class<UserPreferences> clazz) {
        try {
            return new ObjectMapper().readValue(json, clazz);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON解析失败", e);
        }
    }
}

class UserPreferences {
    private List<String> excludedCategories;
    private List<String> includedCategories;
    private Map<String, Object> preferences;

    public List<String> getExcludedCategories() {
        return excludedCategories;
    }

    public List<String> getIncludedCategories() {
        return includedCategories;
    }

    public void addIncludedCategory(String category) {
        includedCategories.add(category);
    }

    public Map<String, Object> getPreferences() {
        return preferences;
    }
}

class Category {
    private String name;
    private boolean valid;

    public String getName() {
        return name;
    }

    public boolean isValid() {
        return valid;
    }
}