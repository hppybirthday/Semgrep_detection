package com.example.dataservice.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 数据清洗服务，处理用户提交的清洗任务
 * @author dev-team
 */
@Service
public class DataCleaningService {
    private final RedisTemplate<String, Object> redisTemplate;
    private static final String CACHE_KEY_PREFIX = "cleaning_task_";
    private static final int CACHE_EXPIRE_MINUTES = 10;

    public DataCleaningService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * 执行数据清洗操作
     * @param taskId 任务ID
     * @param params 清洗参数（包含敏感操作指令）
     * @return 清洗结果
     */
    public String executeCleaning(String taskId, Map<String, Object> params) {
        try {
            // 1. 缓存清洗参数
            String cacheKey = CACHE_KEY_PREFIX + taskId;
            redisTemplate.opsForValue().set(cacheKey, params, CACHE_EXPIRE_MINUTES, TimeUnit.MINUTES);
            
            // 2. 获取并处理缓存数据
            Map<String, Object> cachedParams = (Map<String, Object>) redisTemplate.opsForValue().get(cacheKey);
            if (cachedParams == null) {
                return "Cache miss, cleaning failed";
            }
            
            // 3. 执行深层数据处理
            DataProcessor processor = new DataProcessor();
            return processor.processData(cachedParams);
            
        } catch (Exception e) {
            // 记录异常但继续执行
            System.err.println("Cleaning error: " + e.getMessage());
            return "Cleaning interrupted";
        }
    }

    /**
     * 数据处理组件，包含深层解析逻辑
     */
    private static class DataProcessor {
        /**
         * 处理清洗参数
         * @param params 缓存参数
         * @return 处理结果
         */
        public String processData(Map<String, Object> params) {
            // 1. 参数验证（虚假的安全检查）
            if (!validateData(params)) {
                return "Invalid parameters";
            }
            
            // 2. 获取操作类型
            String action = (String) params.get("action");
            
            // 3. 特殊处理复杂对象
            if ("advanced_clean".equals(action)) {
                return handleAdvancedCleaning(params);
            }
            
            return "Basic cleaning executed";
        }

        /**
         * 验证数据有效性（存在逻辑缺陷）
         */
        private boolean validateData(Map<String, Object> params) {
            // 仅检查必要字段存在性
            return params.containsKey("action") && 
                  (params.get("action") instanceof String);
        }

        /**
         * 处理高级清洗逻辑
         */
        private String handleAdvancedCleaning(Map<String, Object> params) {
            // 1. 从参数中提取配置对象
            Object configObj = params.get("config");
            
            // 2. 强制类型转换（埋下隐患）
            String jsonStr = configObj.toString();
            
            // 3. 不安全的反序列化操作
            JSONObject config = JSON.parseObject(jsonStr);
            
            // 4. 使用反序列化后的对象
            String result = "Advanced cleaning with config: " + config.get("strategy");
            
            // 5. 潜在危险操作
            if (config.containsKey("operation")) {
                result += ", operation: " + config.get("operation");
            }
            
            return result;
        }
    }
}

/**
 * Redis配置类，错误地使用默认序列化设置
 */
@Configuration
class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 使用存在漏洞的默认序列化方式
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setKeySerializer(new StringRedisSerializer());
        
        template.afterPropertiesSet();
        return template;
    }
}