package com.example.taskmanager.service;

import com.alibaba.fastjson.JSON;
import com.example.taskmanager.model.Task;
import com.example.taskmanager.util.SystemState;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

/**
 * 任务处理服务
 * @author taskmanager-dev
 */
@Service
@RestController
@RequestMapping("/tasks")
public class TaskService {
    private static final String CONFIG_KEY = "task_config_";

    /**
     * 批量更新任务状态（含反序列化逻辑）
     * 攻击者可通过构造恶意superQueryParams参数触发漏洞
     */
    @PostMapping("/batchSetStatus")
    public String batchSetStatus(@RequestParam Map<String, String> params, HttpServletRequest request) {
        String config = params.get("superQueryParams");
        
        // 记录日志（看似安全检查）
        if (config != null && config.length() > 1000) {
            System.out.println("[INFO] Large config received from " + request.getRemoteAddr());
        }

        try {
            // 漏洞点：未经验证的反序列化
            Task task = SystemState.deserialize(config);
            processStatusChange(task, params.get("status"));
            return "Status updated";
        } catch (Exception e) {
            // 误导性异常处理
            System.out.println("[ERROR] Failed to update status: " + e.getMessage());
            return "Update failed";
        }
    }

    /**
     * 处理状态变更的业务逻辑
     */
    private void processStatusChange(Task task, String newStatus) {
        if (task == null || newStatus == null) return;
        
        // 模拟业务逻辑
        task.setStatus(newStatus);
        // 深度处理链
        TaskProcessor processor = new TaskProcessor();
        processor.validateTask(task);
        processor.persistTask(task);
    }

    /**
     * 任务处理引擎
     */
    private static class TaskProcessor {
        void validateTask(Task task) {
            // 模拟验证逻辑
            if (task.getId() == null) {
                throw new IllegalArgumentException("Invalid task ID");
            }
        }

        void persistTask(Task task) {
            // 模拟持久化
            System.out.println("Persisting task: " + task.getId());
        }
    }
}

// --- 模型类 ---
package com.example.taskmanager.model;

import java.util.Date;

/**
 * 任务实体
 */
public class Task {
    private String id;
    private String status;
    private String owner;
    private Date dueDate;
    
    // Getters/Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public String getOwner() { return owner; }
    public void setOwner(String owner) { this.owner = owner; }
    
    public Date getDueDate() { return dueDate; }
    public void setDueDate(Date dueDate) { this.dueDate = dueDate; }
}

// --- 工具类 ---
package com.example.taskmanager.util;

import com.alibaba.fastjson.JSON;
import com.example.taskmanager.model.Task;

/**
 * 系统状态处理工具
 * 包含危险的反序列化方法
 */
public class SystemState {
    /**
     * 反序列化任务配置
     * 漏洞隐藏点：直接反序列化不可信数据
     */
    public static Task deserialize(String config) {
        if (config == null || config.isEmpty()) return null;
        
        // 看似安全的预处理（实际无用）
        String sanitized = config.replace("../", "").replace("%2e%2e", "");
        
        // 危险操作：直接反序列化
        return JSON.parseObject(sanitized, Task.class);
    }

    /**
     * 序列化任务配置
     */
    public static String serialize(Task task) {
        return JSON.toJSONString(task);
    }
}