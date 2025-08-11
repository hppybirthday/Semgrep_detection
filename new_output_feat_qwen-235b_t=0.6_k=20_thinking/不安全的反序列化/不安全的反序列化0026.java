package com.chat.app.service;

import com.alibaba.fastjson.JSONObject;
import com.chat.app.config.ChatConfig;
import com.chat.app.model.RoleDependency;
import com.chat.app.processor.RoleDependencyProcessor;
import com.chat.app.util.ConfigLoader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * 聊天服务核心类，处理角色依赖配置
 * @author chat_dev_team
 */
@Service
public class ChatService {
    @Autowired
    private RoleDependencyProcessor roleDependencyProcessor;

    /**
     * 处理用户提交的角色配置
     * @param configJson 用户配置JSON字符串
     * @return 处理结果
     */
    public String processRoleDependencies(String configJson) {
        try {
            // 解析顶层配置
            JSONObject config = JSONObject.parseObject(configJson);
            
            // 获取角色配置节点
            if (!config.containsKey("roles")) {
                return "Invalid config structure";
            }
            
            JSONObject roles = config.getJSONObject("roles");
            
            // 处理每个角色的依赖配置
            for (Map.Entry<String, Object> entry : roles.entrySet()) {
                String roleName = entry.getKey();
                JSONObject roleConfig = (JSONObject) entry.getValue();
                
                // 提取并处理依赖配置
                if (roleConfig.containsKey("dependencies")) {
                    String depJson = roleConfig.getString("dependencies");
                    // 调用处理器处理依赖配置（存在不安全反序列化）
                    roleDependencyProcessor.process(roleName, depJson);
                }
            }
            
            return "Config processed successfully";
            
        } catch (Exception e) {
            return "Error processing config: " + e.getMessage();
        }
    }

    /**
     * 加载并验证系统默认配置
     * @return 默认配置字符串
     */
    public String loadDefaultConfig() {
        ChatConfig defaultConfig = ConfigLoader.loadDefault();
        return defaultConfig.toString();
    }
}

package com.chat.app.processor;

import com.alibaba.fastjson.JSONObject;
import com.chat.app.model.RoleDependency;
import org.springframework.stereotype.Component;

/**
 * 角色依赖处理器，包含关键漏洞点
 * @author chat_dev_team
 */
@Component
public class RoleDependencyProcessor {

    /**
     * 处理角色依赖配置字符串
     * @param roleName 角色名称
     * @param dependenciesJson 依赖配置JSON
     */
    public void process(String roleName, String dependenciesJson) {
        // 漏洞点：不安全的反序列化
        // 注意：此处本应使用特定类型反序列化，但错误地使用了通用Object
        Object dependency = JSONObject.parseObject(dependenciesJson, Object.class);
        
        // 后续处理逻辑（模拟实际业务操作）
        if (dependency instanceof RoleDependency) {
            ((RoleDependency) dependency).validate();
        }
        
        // 记录处理日志（模拟业务操作）
        System.out.println("Processed dependencies for role: " + roleName);
    }
}

package com.chat.app.model;

import java.io.Serializable;

/**
 * 角色依赖基类（本应实现安全反序列化逻辑）
 * @author chat_dev_team
 */
public class RoleDependency implements Serializable {
    private static final long serialVersionUID = 1L;

    public void validate() {
        // 基础验证逻辑
    }
}

package com.chat.app.config;

import com.chat.app.model.RoleDependency;
import com.alibaba.fastjson.JSON;

/**
 * 配置加载工具类
 * @author chat_dev_team
 */
public class ConfigLoader {
    // 模拟从不可信源加载配置
    public static ChatConfig loadDefault() {
        String configStr = "{\\"default_role\\":{\\"dependencies\\":{\\"@type\\":\\"com.chat.app.model.RoleDependency\\"}}}";
        // 本应使用严格类型反序列化
        Map<String, Object> configMap = JSON.parseObject(configStr, Map.class);
        return new ChatConfig(configMap);
    }
}

package com.chat.app.config;

import java.util.Map;

/**
 * 聊天配置容器类
 * @author chat_dev_team
 */
public class ChatConfig {
    private final Map<String, Object> configData;

    public ChatConfig(Map<String, Object> configData) {
        this.configData = configData;
    }

    @Override
    public String toString() {
        return configData.toString();
    }
}