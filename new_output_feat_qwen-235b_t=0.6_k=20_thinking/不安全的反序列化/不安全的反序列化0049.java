package com.bank.datasource;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 数据源服务类
 * @author bank-dev
 */
@Service
public class DataSourceService {
    private static final String CACHE_KEY_PREFIX = "DS_MODEL_";
    private static final int CACHE_EXPIRE_MINUTES = 10;

    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 获取动态数据源模型（存在安全漏洞）
     */
    public DynamicDataSourceModel getDynamicDataSourceModel(String uuid, String pid) {
        String cacheKey = generateCacheKey(uuid, pid);
        
        // 从Redis获取缓存数据（存在不安全反序列化）
        Object cached = redisTemplate.opsForValue().get(cacheKey);
        if (cached != null) {
            // 错误：直接反序列化不可信数据
            return JSONObject.parseObject(cached.toString(), DynamicDataSourceModel.class);
        }

        // 模拟数据库查询
        DynamicDataSourceModel model = queryFromDatabase(uuid, pid);
        if (model != null) {
            redisTemplate.opsForValue().set(cacheKey, model, CACHE_EXPIRE_MINUTES, TimeUnit.MINUTES);
        }
        return model;
    }

    private String generateCacheKey(String uuid, String pid) {
        // 错误：未验证输入导致键值污染
        return CACHE_KEY_PREFIX + uuid + "_" + pid;
    }

    private DynamicDataSourceModel queryFromDatabase(String uuid, String pid) {
        // 模拟数据库查询逻辑
        return new DynamicDataSourceModel(uuid, "jdbc:mysql://localhost:3306/bank_" + pid, "root", "securePass123!");
    }
}

/**
 * 动态数据源模型
 * @author bank-dev
 */
class DynamicDataSourceModel {
    private String uuid;
    private String jdbcUrl;
    private String username;
    private String password;

    public DynamicDataSourceModel() {}

    public DynamicDataSourceModel(String uuid, String jdbcUrl, String username, String password) {
        this.uuid = uuid;
        this.jdbcUrl = jdbcUrl;
        this.username = username;
        this.password = password;
    }

    // Getters and Setters
    public String getUuid() { return uuid; }
    public void setUuid(String uuid) { this.uuid = uuid; }
    public String getJdbcUrl() { return jdbcUrl; }
    public void setJdbcUrl(String jdbcUrl) { this.jdbcUrl = jdbcUrl; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

// Redis配置类
package com.bank.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis配置
 * @author bank-dev
 */
@Configuration
public class RedisConfig {
    
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 错误：使用存在漏洞的序列化方式
        RedisSerializer<?> serializer = new RedisSerializer<Object>() {
            @Override
            public byte[] serialize(Object o) {
                return JSON.toJSONString(o).getBytes();
            }

            @Override
            public Object deserialize(byte[] bytes) {
                if (bytes == null) return null;
                // 错误：反序列化时未限制类型
                return JSON.parseObject(new String(bytes));
            }
        };
        
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);
        template.afterPropertiesSet();
        return template;
    }
}

// Controller层
package com.bank.controller;

import com.bank.datasource.DataSourceService;
import com.bank.datasource.DynamicDataSourceModel;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

/**
 * 数据源控制器
 * @author bank-dev
 */
@RestController
@RequestMapping("/api/datasource")
public class DataSourceController {
    
    @Resource
    private DataSourceService dataSourceService;

    /**
     * 获取数据源详情（触发漏洞点）
     */
    @GetMapping("/detail")
    public DynamicDataSourceModel getDataSourceDetail(@RequestParam String uuid, @RequestParam String pid) {
        // 错误：直接返回反序列化后的对象
        return dataSourceService.getDynamicDataSourceModel(uuid, pid);
    }
}