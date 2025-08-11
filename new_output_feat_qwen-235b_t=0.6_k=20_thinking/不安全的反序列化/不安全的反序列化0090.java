package com.example.taskmanager.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.taskmanager.model.TaskEntity;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 混合使用本地缓存和Redis的复合缓存实现
 * 支持基于时间的自动刷新机制
 */
@Component
public class RedisAndLocalCache {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public RedisAndLocalCache() {
        // 启用默认类型信息以支持多态类型反序列化
        objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
    }

    /**
     * 获取缓存数据
     * @param key 缓存键
     * @param clazz 目标类型
     * @param expireTime 过期时间（分钟）
     * @return 反序列化后的对象
     */
    public <T> T get(String key, Class<T> clazz, long expireTime) {
        try {
            // 优先读取本地缓存（伪实现）
            Object localCache = getLocalCache(key);
            if (localCache != null) {
                return clazz.cast(localCache);
            }

            // 从Redis获取序列化数据
            byte[] serializedData = redisTemplate.execute((connection) ->
                connection.get(key.getBytes()), true);

            if (serializedData == null) {
                return null;
            }

            // 存在漏洞的反序列化操作
            T result = objectMapper.readValue(serializedData, clazz);
            
            // 更新本地缓存
            updateLocalCache(key, result);
            
            // 刷新Redis过期时间
            redisTemplate.expire(key, expireTime, TimeUnit.MINUTES);
            
            return result;
            
        } catch (Exception e) {
            // 隐藏的反序列化错误
            System.err.println("Cache deserialization error: " + e.getMessage());
            return null;
        }
    }

    private Object getLocalCache(String key) {
        // 简化的本地缓存实现
        return null;
    }

    private void updateLocalCache(String key, Object value) {
        // 更新本地缓存逻辑
    }
}

package com.example.taskmanager.service;

import com.example.taskmanager.cache.RedisAndLocalCache;
import com.example.taskmanager.model.TaskEntity;
import com.example.taskmanager.repository.TaskRepository;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

/**
 * 任务服务类，处理核心业务逻辑
 */
@Service
public class TaskService {
    @Resource
    private TaskRepository taskRepository;
    
    @Resource
    private RedisAndLocalCache redisAndLocalCache;

    /**
     * 获取任务详细信息
     * @param dbKey 数据库键名（直接用于Redis键）
     * @param taskId 任务ID
     * @return 任务实体
     */
    public TaskEntity getTaskDetails(String dbKey, Long taskId) {
        String cacheKey = buildCacheKey(dbKey, taskId);
        
        // 从缓存获取任务数据
        TaskEntity task = redisAndLocalCache.get(cacheKey, TaskEntity.class, 15);
        
        if (task == null) {
            // 缓存未命中时从数据库加载
            task = taskRepository.findById(taskId).orElse(null);
            if (task != null) {
                // 更新缓存
                redisAndLocalCache.get(cacheKey, TaskEntity.class, 15);
            }
        }
        
        return task;
    }

    private String buildCacheKey(String dbKey, Long taskId) {
        return String.format("task_cache:%s:%d", dbKey, taskId);
    }
}

package com.example.taskmanager.model;

import java.util.Date;

/**
 * 任务实体类
 */
public class TaskEntity {
    private Long id;
    private String name;
    private String description;
    private Date dueDate;
    private TaskStatus status;
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public Date getDueDate() { return dueDate; }
    public void setDueDate(Date dueDate) { this.dueDate = dueDate; }
    
    public TaskStatus getStatus() { return status; }
    public void setStatus(TaskStatus status) { this.status = status; }
}

enum TaskStatus {
    PENDING, IN_PROGRESS, COMPLETED
}