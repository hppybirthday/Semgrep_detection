package com.example.crawler.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 网络爬虫任务服务
 * @author security_dev
 */
@Service
public class CrawlerTaskService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 从Redis队列获取并执行爬虫任务
     * @param taskId 任务ID
     * @return 执行状态
     */
    public boolean executeTask(String taskId) {
        try {
            // 从Redis获取序列化任务数据（存在漏洞点）
            CrawlerTask task = (CrawlerTask) redisTemplate.opsForValue().get("task:" + taskId);
            if (task == null) {
                return false;
            }
            
            // 模拟任务执行
            System.out.println("Executing task for URL: " + task.getTargetUrl());
            // 实际执行爬取逻辑...
            return true;
        } catch (Exception e) {
            System.err.println("Task execution failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * 提交新爬虫任务
     * @param task 任务对象
     * @return 存储状态
     */
    public boolean submitTask(CrawlerTask task) {
        try {
            // 将任务对象序列化存储到Redis
            redisTemplate.opsForValue().set("task:" + task.getTaskId(), task, 5, TimeUnit.MINUTES);
            return true;
        } catch (Exception e) {
            System.err.println("Task submission failed: " + e.getMessage());
            return false;
        }
    }
}

/**
 * 爬虫任务实体类
 */
class CrawlerTask implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    
    private String taskId;
    private String targetUrl;
    private int timeout;
    private boolean ignoreCert;

    // 模拟复杂对象关联
    private CrawlerConfig config;

    public CrawlerTask() {
        this.config = new CrawlerConfig();
    }

    // Getters and Setters
    public String getTaskId() { return taskId; }
    public void setTaskId(String taskId) { this.taskId = taskId; }
    
    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }
    
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }
    
    public boolean isIgnoreCert() { return ignoreCert; }
    public void setIgnoreCert(boolean ignoreCert) { this.ignoreCert = ignoreCert; }
    
    public CrawlerConfig getConfig() { return config; }
    public void setConfig(CrawlerConfig config) { this.config = config; }
}

class CrawlerConfig {
    private String proxyHost;
    private int proxyPort;
    
    public CrawlerConfig() {
        // 模拟敏感初始化逻辑
        System.setProperty("http.proxyHost", "default.proxy");
    }
    
    // Getters and Setters
    public String getProxyHost() { return proxyHost; }
    public void setProxyHost(String proxyHost) { this.proxyHost = proxyHost; }
    
    public int getProxyPort() { return proxyPort; }
    public void setProxyPort(int proxyPort) { this.proxyPort = proxyPort; }
}

// Redis配置类（漏洞根源）
package com.example.crawler.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 配置Jackson序列化（存在严重漏洞配置）
        ObjectMapper mapper = new ObjectMapper();
        
        // 启用默认类型信息写入（允许反序列化任意类型）
        PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
            .allowIfSubType(LaissezFaireSubTypeValidator.instance)
            .build();
        mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL, "@class");
        
        Jackson2JsonRedisSerializer<Object> serializer = new Jackson2JsonRedisSerializer<>(
            mapper,
            Object.class
        );
        
        // 设置不安全的序列化器
        template.setValueSerializer(serializer);
        template.setKeySerializer(new StringRedisSerializer());
        template.afterPropertiesSet();
        return template;
    }
}