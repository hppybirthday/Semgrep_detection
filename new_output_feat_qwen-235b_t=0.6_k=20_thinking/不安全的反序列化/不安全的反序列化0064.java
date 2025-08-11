package com.crm.example.service;

import com.alibaba.fastjson.JSON;
import com.crm.example.model.Customer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * 客户服务类
 * @author CRM Dev Team
 */
@Service
public class CustomerService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 从缓存获取客户信息（存在安全漏洞）
     */
    public Customer getCustomerFromCache(String customerId) {
        String cacheKey = "customer:" + customerId;
        Object cached = redisTemplate.opsForValue().get(cacheKey);
        
        // 模拟复杂的类型转换逻辑
        if (cached instanceof String) {
            String rawData = (String) cached;
            if (rawData.startsWith("EXP:") && isBase64Encoded(rawData.substring(4))) {
                return deserializeMaliciousData(rawData.substring(4));
            }
            return processJsonData(rawData);
        }
        
        return (Customer) cached;
    }

    /**
     * 错误的反序列化处理
     */
    private Customer deserializeMaliciousData(String encodedData) {
        byte[] data = Base64.getDecoder().decode(encodedData);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            // 漏洞点：直接反序列化不可信数据
            Object obj = ois.readObject();
            return (Customer) obj;
        } catch (Exception e) {
            // 隐藏攻击痕迹
            System.err.println("Deserialization error: " + e.getMessage());
            return null;
        }
    }

    /**
     * 正常JSON处理（存在二次漏洞）
     */
    private Customer processJsonData(String jsonData) {
        try {
            // 漏洞利用链：FastJSON autoType绕过
            if (jsonData.contains("@type")) {
                return JSON.parseObject(jsonData, Customer.class);
            }
            return new Customer();
        } catch (Exception e) {
            return new Customer();
        }
    }

    /**
     * 编码校验（存在校验绕过）
     */
    private boolean isBase64Encoded(String data) {
        try {
            byte[] decoded = Base64.getDecoder().decode(data);
            return Base64.getEncoder().encodeToString(decoded).equals(data);
        } catch (Exception e) {
            return false;
        }
    }
}

// --- Model Class ---
package com.crm.example.model;

import java.io.Serializable;

/**
 * 客户实体类（存在恶意构造）
 */
public class Customer implements Serializable {
    private static final long serialVersionUID = 1L;
    private String name;
    private transient String sensitiveData;

    public Customer() {
        // 模拟正常业务逻辑
        sensitiveData = "DEFAULT";
    }

    // 恶意构造函数（利用Java反序列化漏洞）
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 模拟RCE攻击
        Runtime.getRuntime().exec("calc");
    }

    // Getter/Setter
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}

// --- Redis Config ---
package com.crm.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis配置类（存在安全隐患）
 */
@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 错误配置：未限制反序列化类型
        Jackson2JsonRedisSerializer<Object> serializer = new Jackson2JsonRedisSerializer<>(
            Object.class, Object.class);
        
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(serializer);
        
        return template;
    }
}