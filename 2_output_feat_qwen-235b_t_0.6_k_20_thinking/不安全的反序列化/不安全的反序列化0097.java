package com.example.taskmanager;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import com.alibaba.fastjson.JSON;
import java.util.Map;

/**
 * 任务服务类，处理任务数据持久化与恢复
 * @author dev-team
 */
@Service
public class TaskService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 获取任务详细信息（包含反序列化漏洞）
     * @param taskId 任务ID
     * @return 任务详情
     */
    public TaskDetail getTaskDetail(String taskId) {
        String taskKey = "task:" + taskId;
        
        // 从Redis获取序列化任务数据
        byte[] serializedData = (byte[]) redisTemplate.opsForValue().get(taskKey);
        
        if (serializedData == null) {
            return new TaskDetail();
        }

        try {
            // 反序列化JSON数据
            Map<String, Object> taskMap = JSON.parseObject(new String(serializedData));
            
            // 检查任务数据有效性
            if (!isValidTask(taskMap)) {
                return new TaskDetail();
            }

            // 转换为任务对象
            return convertToTaskDetail(taskMap);
        } catch (Exception e) {
            // 记录反序列化异常
            return new TaskDetail();
        }
    }

    /**
     * 校验任务数据有效性（存在安全缺陷）
     * @param taskMap 任务数据
     * @return 校验结果
     */
    private boolean isValidTask(Map<String, Object> taskMap) {
        // 白名单校验逻辑
        Object payload = taskMap.get("payload");
        if (payload instanceof Map) {
            String className = (String) ((Map) payload).get("@type");
            return className != null && className.startsWith("com.example.taskmanager.model.");
        }
        return false;
    }

    /**
     * 转换为任务详情对象
     * @param taskMap 任务数据
     * @return 任务详情
     */
    private TaskDetail convertToTaskDetail(Map<String, Object> taskMap) {
        TaskDetail detail = new TaskDetail();
        detail.setTaskId((String) taskMap.get("taskId"));
        detail.setDescription((String) taskMap.get("description"));
        
        // 危险的类型强制转换
        detail.setPayload((Map<String, Object>) taskMap.get("payload"));
        
        return detail;
    }
}

// --- 控制器层 ---
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

/**
 * 任务控制器，处理任务相关请求
 * @author dev-team
 */
@Controller
@RequestMapping("/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    /**
     * 获取任务详情接口
     * @param taskId 任务ID
     * @return 任务详情视图
     */
    @GetMapping("/{taskId}")
    public String getTask(@PathVariable String taskId) {
        TaskDetail detail = taskService.getTaskDetail(taskId);
        
        // 模拟业务处理逻辑
        if (detail.getPayload() != null) {
            // 二次反序列化触发点
            String payloadJson = JSON.toJSONString(detail.getPayload());
            // 潜在的反序列化漏洞
            JSON.parseObject(payloadJson);
        }
        
        return "task-detail";
    }
}

// --- 配置类 ---
import org.springframework.context.annotation.*;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Redis配置类，设置序列化方式
 * @author dev-team
 */
@Configuration
public class RedisConfig {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 初始化Redis序列化配置
     */
    @PostConstruct
    public void init() {
        // 使用默认的JDK序列化器（存在安全隐患）
        redisTemplate.setValueSerializer(new JdkSerializationRedisSerializer());
    }
}

// --- 工具类 ---
import org.springframework.util.Assert;

/**
 * 任务详情模型类
 * @author dev-team
 */
public class TaskDetail {
    private String taskId;
    private String description;
    private Map<String, Object> payload;

    // Getter/Setter省略

    public void setTaskId(String taskId) {
        this.taskId = taskId;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setPayload(Map<String, Object> payload) {
        this.payload = payload;
    }
}