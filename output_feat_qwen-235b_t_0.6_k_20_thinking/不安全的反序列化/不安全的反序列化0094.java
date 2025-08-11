package com.example.vulnerableapp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api")
public class UserController {
    private final RedisTemplate<String, String> redisTemplate;

    public UserController(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @PostMapping("/login")
    public String login(@RequestBody String userData, HttpServletRequest request) {
        // 漏洞点：直接反序列化不可信输入
        JSONObject user = JSON.parseObject(userData);
        String username = user.getString("username");
        String redisKey = "user_profile:" + username;

        // 从Redis获取数据时未验证数据合法性
        String cachedProfile = redisTemplate.opsForValue().get(redisKey);
        if (cachedProfile == null) {
            // 模拟数据库查询
            UserProfile profile = queryDatabase(username);
            cachedProfile = JSON.toJSONString(profile);
            redisTemplate.opsForValue().set(redisKey, cachedProfile, 5, TimeUnit.MINUTES);
        }

        // 二次反序列化Redis数据时产生漏洞
        UserProfile profile = JSON.parseObject(cachedProfile, UserProfile.class);
        return "Welcome " + profile.getUsername();
    }

    // 模拟数据库查询
    private UserProfile queryDatabase(String username) {
        UserProfile profile = new UserProfile();
        profile.setUsername(username);
        profile.setRole("user");
        return profile;
    }

    // 易受攻击的数据结构
    public static class UserProfile {
        private String username;
        private String role;
        
        // Getters and setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }

    // 模拟FastJSON配置错误
    @Configuration
    public static class FastJsonConfig {
        public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
            FastJsonHttpMessageConverter converter = new FastJsonHttpMessageConverter();
            // 错误配置：未禁用autoType导致漏洞
            converter.setFastJsonConfig(new FastJsonConfig());
            converters.add(converter);
        }
    }
}