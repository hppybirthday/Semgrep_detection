package com.example.security.vuln;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.*;

@RestController
@RequestMapping("/users")
public class UserController {
    @Resource
    private UserService userService;
    
    @PostMapping("/export")
    public String exportUsers(@RequestBody Map<String, Object> config) {
        try {
            // 漏洞点：将用户输入直接转换为ConfigMap对象
            ConfigMap configMap = new ObjectMapper().convertValue(config, ConfigMap.class);
            List<User> users = userService.getUsers(configMap);
            return "Exported " + users.size() + " users";
        } catch (Exception e) {
            return "Export failed: " + e.getMessage();
        }
    }
}

class ConfigMap {
    private Map<String, Object> filters;
    private List<String> fields;
    
    // 漏洞点：自动类型转换触发反序列化
    public void setFilters(Map<String, Object> filters) {
        this.filters = filters;
    }
}

@Service
class UserService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    public List<User> getUsers(ConfigMap config) throws IOException {
        String cacheKey = generateCacheKey(config);
        
        // 漏洞点：从Redis获取缓存时触发反序列化
        @SuppressWarnings("unchecked")
        List<User> cached = (List<User>) redisTemplate.opsForValue().get(cacheKey);
        
        if (cached != null) {
            return cached;
        }
        
        // 模拟数据库查询
        List<User> result = queryDatabase(config);
        redisTemplate.opsForValue().set(cacheKey, result, 5, TimeUnit.MINUTES);
        return result;
    }
    
    private String generateCacheKey(ConfigMap config) {
        // 漏洞点：使用FastJSON序列化配置对象
        return "user_cache:" + JSON.toJSONString(config);
    }
    
    private List<User> queryDatabase(ConfigMap config) {
        // 模拟数据库查询逻辑
        return Arrays.asList(new User("admin"), new User("guest"));
    }
}

@Configuration
class RedisConfig {
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(factory);
        
        // 漏洞点：使用JDK原生序列化
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.setKeySerializer(new StringRedisSerializer());
        template.afterPropertiesSet();
        
        return template;
    }
}

// 模拟存在漏洞的FastJSON配置
class JSONConfig {
    static {
        // 漏洞点：启用不安全的autoType
        System.setProperty("fastjson.parser.autoTypeSupport", "true");
    }
}

// 模拟用户实体类
class User {
    private String username;
    
    public User(String username) {
        this.username = username;
    }
    
    // 漏洞利用链示例
    public static Transformer[] getChainedTransformer() {
        return new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
    }
}