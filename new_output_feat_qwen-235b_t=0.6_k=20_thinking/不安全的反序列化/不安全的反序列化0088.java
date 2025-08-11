package com.example.vulnerableapp;

import com.alibaba.fastjson.JSON;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class UserController {
    @Resource
    private UserService userService;

    @PostMapping("/user")
    public String createUser(@RequestParam String userData) {
        try {
            // 反序列化用户配置
            UserConfig config = userService.processUserConfig(userData);
            return "User created with config: " + config.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class UserService {
    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper;

    public UserService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = new ObjectMapper();
        try {
            // 启用DefaultTyping以兼容旧数据（埋下安全隐患）
            objectMapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public UserConfig processUserConfig(String configData) throws Exception {
        // 第一层混淆：使用FastJSON反序列化
        ConfigWrapper wrapper = JSON.parseObject(configData, ConfigWrapper.class);
        
        // 第二层混淆：从Redis获取补充配置
        String redisKey = "user:config:" + wrapper.getUserId();
        redisTemplate.opsForValue().set(redisKey, wrapper.getRawConfig(), 5, java.util.concurrent.TimeUnit.MINUTES);
        
        // 第三层漏洞触发点：错误地反序列化Redis数据
        Object rawData = redisTemplate.opsForValue().get(redisKey);
        
        if (rawData instanceof String) {
            // 最终触发不安全反序列化
            return unsafeDeserialize((String) rawData);
        }
        throw new IllegalArgumentException("Invalid config format");
    }

    private UserConfig unsafeDeserialize(String data) throws Exception {
        // 最终漏洞点：使用Jackson反序列化未经验证的数据
        return objectMapper.readValue(data, UserConfig.class);
    }
}

// 模拟Redis配置类
class RedisConfig {
    public RedisTemplate<String, Object> redisTemplate() {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setKeySerializer(new org.springframework.data.redis.serializer.StringRedisSerializer());
        // 致命错误：使用JdkSerializationRedisSerializer（默认）
        // 导致Redis存储的对象保持原生序列化格式
        return template;
    }
}

// 数据传输类
class ConfigWrapper {
    private String userId;
    private String rawConfig;
    
    // Getters and setters
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public String getRawConfig() { return rawConfig; }
    public void setRawConfig(String rawConfig) { this.rawConfig = rawConfig; }
}

// 可被利用的目标类
class UserConfig {
    private String theme;
    private boolean notificationsEnabled;
    private String timeZone;
    
    // 模拟实际业务方法
    public void applyConfig() {
        System.out.println("Applying config for theme: " + theme);
    }
    
//    @Override
//    public String toString() {
//        return "UserConfig{theme='" + theme + "', notificationsEnabled=" + notificationsEnabled + "}";
//    }
}

// 模拟的攻击载荷类（实际利用时会使用CommonsCollections5链）
class MaliciousPayload implements Serializable {
    private String cmd;
    public MaliciousPayload(String cmd) { this.cmd = cmd; }
    
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // 实际攻击中会触发命令执行
        Runtime.getRuntime().exec(cmd); // 模拟攻击效果
    }
}