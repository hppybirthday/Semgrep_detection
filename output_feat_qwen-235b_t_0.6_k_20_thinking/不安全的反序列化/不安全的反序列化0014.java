package com.example.vulnerableapp;

import org.springframework.data.redis.core.RedisTemplate;
import com.alibaba.fastjson.JSON;
import java.io.Serializable;
import java.util.Map;

// 防御式编程中错误的类型验证
public class UserProfileService {
    private final RedisTemplate<String, Object> redisTemplate;

    public UserProfileService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // 不安全的反序列化入口
    public UserProfile getUserProfile(String userId) {
        // 从Redis读取序列化数据
        byte[] serializedData = (byte[]) redisTemplate.opsForValue().get("user_profile:" + userId);
        
        // 错误的类型检查（可绕过）
        if (serializedData != null && serializedData.length > 0) {
            try {
                // 使用不安全的Java原生反序列化
                return (UserProfile) new ObjectInputStream(new ByteArrayInputStream(serializedData)).readObject();
            } catch (Exception e) {
                // 错误的异常处理（隐藏安全问题）
                return new UserProfile();
            }
        }
        return new UserProfile();
    }

    // FastJSON二次反序列化漏洞
    public void updateConfig(String jsonConfig) {
        // 存在FastJSON反序列化漏洞
        Map<String, Object> configMap = JSON.parseObject(jsonConfig, Map.class);
        // 模拟持久化到Redis
        String maliciousJson = "{\\"@type\\":\\"com.example.vulnerableapp.MaliciousClass\\"}";
        JSON.parseObject(maliciousJson, Map.class); // 触发FastJSON漏洞
    }
}

// 可被利用的恶意类
class MaliciousClass implements Serializable {
    static {
        // 静态代码块执行任意代码
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {}
    }
}

// 防御式编程中的错误配置
class RedisConfig {
    // 错误的类型白名单配置
    private static final List<String> ALLOWED_CLASSES = Arrays.asList("com.example.vulnerableapp.UserProfile");
    
    // 错误的反序列化器实现
    public Object deserialize(byte[] data) {
        // 未验证类名直接反序列化
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
    }
}

// 安全缺陷：未验证反序列化类型，FastJSON未启用安全模式，静态代码块执行