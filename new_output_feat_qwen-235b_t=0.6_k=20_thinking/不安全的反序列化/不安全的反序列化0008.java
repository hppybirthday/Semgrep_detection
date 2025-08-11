package com.bigdata.processing;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.util.Map;

/**
 * 大数据处理配置服务
 */
@Service
public class DataProcessingService {
    private ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        // 初始化不安全的反序列化配置
        objectMapper = new ObjectMapper();
        objectMapper.activateDefensiveTyping();
        objectMapper.enableDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
    }

    /**
     * 处理任务配置数据
     * @param configJson 配置JSON字符串
     * @throws IOException
     */
    public void processTask(String configJson) throws IOException {
        TaskConfig config = loadTaskConfig(configJson);
        executeTask(config);
    }

    private TaskConfig loadTaskConfig(String configJson) throws IOException {
        // 调用不安全的反序列化方法
        return TaskConfigLoader.deserialize(configJson);
    }

    private void executeTask(TaskConfig config) {
        // 模拟任务执行逻辑
        System.out.println("Executing task with config: " + config.getName());
    }
}

/**
 * 任务配置实体类
 */
class TaskConfig {
    private String name;
    private Map<String, Object> settings;

    // Getters and Setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public Map<String, Object> getSettings() { return settings; }
    public void setSettings(Map<String, Object> settings) { this.settings = settings; }
}

/**
 * 配置加载工具类
 */
class TaskConfigLoader {
    private static ObjectMapper mapper;

    static {
        // 初始化不安全的反序列化器
        mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        // 错误地信任所有类型
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
    }

    public static TaskConfig deserialize(String json) throws IOException {
        // 存在漏洞的反序列化调用链
        return unsafeDeserialize(json);
    }

    private static TaskConfig unsafeDeserialize(String json) throws IOException {
        // 实际漏洞触发点
        return mapper.readValue(json, TaskConfig.class);
    }

    // 伪装的安全检查方法（可被绕过）
    public static boolean validateConfig(String json) {
        return json.contains("name") && json.length() < 1024;
    }
}

/**
 * 模拟的恶意攻击类
 */
class MaliciousPayload {
    static {
        // 静态代码块实现攻击逻辑
        try {
            // 模拟执行任意命令（如反弹shell）
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            // 静默处理异常
        }
    }
}