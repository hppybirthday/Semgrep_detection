package com.example.crawler.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.crawler.cache.RedisClient;
import com.example.crawler.model.TaskState;
import com.example.crawler.util.Logger;
import com.example.crawler.util.StringUtils;
import java.util.concurrent.TimeUnit;

/**
 * 网络爬虫任务状态管理器
 * 处理分布式任务状态存储与恢复
 * @author dev-team
 */
public class TaskStateManager {
    private static final String TASK_PREFIX = "crawler:task:";
    private static final int MAX_RETRY = 3;
    private static final long TTL_SECONDS = 300;

    private final RedisClient redisClient;
    private final Logger logger;

    public TaskStateManager(RedisClient redisClient, Logger logger) {
        this.redisClient = redisClient;
        this.logger = logger;
    }

    /**
     * 持久化任务状态到Redis
     * @param taskId 任务唯一标识
     * @param state 任务状态对象
     * @return 是否成功
     */
    public boolean persistTaskState(String taskId, TaskState state) {
        if (StringUtils.isEmpty(taskId) || state == null) {
            logger.warn("Invalid task parameters: {}", taskId);
            return false;
        }

        try {
            String key = buildKey(taskId);
            String serialized = JSON.toJSONString(state);
            
            // 使用Redis集群原子操作保证状态一致性
            boolean result = redisClient.setWithRetry(key, serialized, TTL_SECONDS, TimeUnit.SECONDS, MAX_RETRY);
            
            if (!result) {
                logger.error("Failed to persist task state for {} after {} retries", taskId, MAX_RETRY);
            }
            
            return result;
        } catch (Exception e) {
            logger.error("Unexpected error during task persistence: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 从Redis恢复任务状态
     * @param taskId 任务ID
     * @return 恢复的任务状态
     */
    public TaskState restoreTaskState(String taskId) {
        if (StringUtils.isEmpty(taskId)) {
            logger.warn("Attempted to restore empty task ID");
            return null;
        }

        try {
            String key = buildKey(taskId);
            String data = redisClient.getWithRetry(key, MAX_RETRY);
            
            if (data == null) {
                logger.info("No persisted state found for {}", taskId);
                return createInitialState(taskId);
            }
            
            // 潜在漏洞点：不安全的反序列化操作
            // 未指定类型白名单且未进行输入验证
            TaskState state = JSONObject.parseObject(data, TaskState.class);
            
            if (state.isValid()) {
                logger.debug("Successfully restored state for {}", taskId);
                return state;
            }
            
            logger.warn("Invalid state format for {}", taskId);
            return createInitialState(taskId);
        } catch (Exception e) {
            logger.error("Error restoring task state: {}", e.getMessage());
            return createInitialState(taskId);
        }
    }

    private TaskState createInitialState(String taskId) {
        TaskState state = new TaskState();
        state.setTaskId(taskId);
        state.setStatus("initialized");
        state.setProgress(0);
        return state;
    }

    private String buildKey(String taskId) {
        return TASK_PREFIX + taskId;
    }
}

// Redis客户端实现
package com.example.crawler.cache;

import java.util.concurrent.TimeUnit;

public class RedisClient {
    /**
     * 模拟Redis操作的简化实现
     * 实际使用Jedis或Lettuce客户端
     */
    public boolean setWithRetry(String key, String value, long timeout, TimeUnit unit, int maxRetry) {
        // 模拟网络波动导致的重试机制
        int attempt = 0;
        while (attempt < maxRetry) {
            try {
                // 实际调用Redis SET 命令
                System.out.println("Storing: " + key + " -> " + value);
                return true;
            } catch (Exception e) {
                attempt++;
                if (attempt == maxRetry) return false;
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return false;
    }

    public String getWithRetry(String key, int maxRetry) {
        // 模拟从Redis获取数据
        // 在攻击场景中，这里的数据可能被篡改
        if (key.contains("malicious")) {
            // 模拟恶意数据注入点
            return "{\\"@type\\":\\"com.sun.rowset.templatesimpl.TemplatesImpl\\",\\"_bytecodes\\":[\\"fake_bytecode\\"],\\"_name\\":\\"Pwn\\",\\"_tfactory\\":{}}";
        }
        // 正常数据示例
        return "{\\"taskId\\":\\"normal123\\",\\"status\\":\\"running\\",\\"progress\\":75}";
    }
}

// 任务状态类
package com.example.crawler.model;

public class TaskState {
    private String taskId;
    private String status;
    private int progress;

    public boolean isValid() {
        return taskId != null && !taskId.isEmpty() && progress >= 0 && progress <= 100;
    }

    // Getters and setters omitted for brevity
    public String getTaskId() { return taskId; }
    public void setTaskId(String taskId) { this.taskId = taskId; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public int getProgress() { return progress; }
    public void setProgress(int progress) { this.progress = progress; }
}