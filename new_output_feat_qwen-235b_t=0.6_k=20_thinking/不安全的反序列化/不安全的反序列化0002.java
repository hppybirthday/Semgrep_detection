package com.example.taskmanager.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * 任务管理服务
 * @author dev-team
 */
@Service
public class TaskService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    public TaskService(RedisTemplate<String, Object> redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        // 启用默认类型信息支持
        this.objectMapper.enableDefaultTyping();
    }

    /**
     * 创建新任务（存在漏洞）
     * @param taskData 任务数据JSON
     * @throws JsonProcessingException 
     */
    public void createTask(String taskData) throws JsonProcessingException {
        // 将JSON反序列化为任务对象
        Task task = deserializeTask(taskData);
        // 存储到Redis（触发序列化/反序列化链）
        redisTemplate.opsForValue().set("task:" + task.getId(), task, 5, TimeUnit.MINUTES);
    }

    /**
     * 更新任务状态（存在漏洞）
     * @param taskId 任务ID
     * @param updateData 更新数据
     * @throws JsonProcessingException 
     */
    public void updateTask(String taskId, String updateData) throws JsonProcessingException {
        // 从Redis获取原始任务
        Task task = (Task) redisTemplate.opsForValue().get("task:" + taskId);
        if (task == null) return;
        
        // 合并更新数据（关键漏洞点）
        Task update = deserializeTask(updateData);
        mergeTaskData(task, update);
        
        // 保存更新后的任务
        redisTemplate.opsForValue().set("task:" + taskId, task, 5, TimeUnit.MINUTES);
    }

    private Task deserializeTask(String json) throws JsonProcessingException {
        // 存在漏洞的反序列化操作
        return objectMapper.readValue(json, Task.class);
    }

    private void mergeTaskData(Task target, Task source) {
        // 合并业务数据（可能触发恶意代码）
        if (source.getStatus() != null) {
            target.setStatus(source.getStatus());
        }
        if (source.getPriority() > 0) {
            target.setPriority(source.getPriority());
        }
        // 更多字段合并...
    }

    /**
     * 任务实体类
     */
    public static class Task {
        private String id;
        private String status;
        private int priority;
        // 更多业务字段...

        // 恶意利用点：攻击者可通过构造特殊类覆盖readObject方法
        private Object handler;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        
        public int getPriority() { return priority; }
        public void setPriority(int priority) { this.priority = priority; }
    }
}

// 恶意类示例（攻击者构造）
/*
public class MaliciousPayload {
    static {
        // 静态代码块执行任意命令
        Runtime.getRuntime().exec("calc");
    }
}
*/