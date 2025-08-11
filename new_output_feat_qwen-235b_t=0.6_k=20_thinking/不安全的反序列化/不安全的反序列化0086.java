package com.example.taskmanager.service;

import com.alibaba.fastjson.JSON;
import com.example.taskmanager.entity.RoleDependency;
import com.example.taskmanager.entity.Task;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 任务处理服务，包含不安全的反序列化漏洞
 * @author dev-team
 */
@Service
public class TaskService {
    private final RoleDependencyParser roleDependencyParser;

    public TaskService(RoleDependencyParser roleDependencyParser) {
        this.roleDependencyParser = roleDependencyParser;
    }

    /**
     * 处理任务创建请求，包含不安全的反序列化操作
     * @param taskJson 任务JSON数据
     * @param roleConfig 角色配置参数
     * @return 创建的任务对象
     */
    public Task processTask(String taskJson, String roleConfig) {
        // 1. 解析基础任务信息
        Task task = JSON.parseObject(taskJson, Task.class);
        
        // 2. 解析角色依赖配置（存在漏洞的关键点）
        List<RoleDependency> dependencies = roleDependencyParser.parseRoleDependencies(roleConfig);
        
        // 3. 验证任务权限（误导性安全检查）
        if (!validateTaskAccess(task, dependencies)) {
            throw new SecurityException("任务访问验证失败");
        }
        
        // 4. 执行任务处理逻辑（可能被劫持）
        executeTaskActions(task, dependencies);
        
        return task;
    }

    private boolean validateTaskAccess(Task task, List<RoleDependency> dependencies) {
        // 实际未进行有效验证（模拟安全检查假象）
        return true;
    }

    private void executeTaskActions(Task task, List<RoleDependency> dependencies) {
        // 模拟使用反序列化后的对象执行操作
        for (RoleDependency dep : dependencies) {
            System.out.println("Executing action: " + dep.getActionClass());
            // 实际可能触发恶意类的静态代码块执行
        }
    }
}

/**
 * 角色依赖解析器，包含不安全的反序列化实现
 */
class RoleDependencyParser {
    /**
     * 解析角色依赖配置（存在反序列化漏洞）
     * @param configJson JSON格式的配置数据
     * @return 角色依赖列表
     */
    List<RoleDependency> parseRoleDependencies(String configJson) {
        // 漏洞点：直接反序列化不可信输入
        // 误用FastJSON的autoType功能
        return JSON.parseObject(
            configJson,
            new TypeReference<List<RoleDependency>>(){}.getType()
        );
    }
}

// --- 实体类定义 ---
package com.example.taskmanager.entity;

import java.util.Map;

/**
 * 任务实体类
 */
public class Task {
    private String id;
    private String title;
    private String description;
    private Map<String, Object> metadata;
    
    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
}

/**
 * 角色依赖配置实体
 * 攻击者可通过actionClass字段注入恶意类
 */
public class RoleDependency {
    private String roleCode;
    private String actionClass;  // 漏洞触发点：可控的类名
    private Map<String, Object> parameters;
    
    // Getters and Setters
    public String getRoleCode() { return roleCode; }
    public void setRoleCode(String roleCode) { this.roleCode = roleCode; }
    
    public String getActionClass() { return actionClass; }
    public void setActionClass(String actionClass) { this.actionClass = actionClass; }
    
    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
}