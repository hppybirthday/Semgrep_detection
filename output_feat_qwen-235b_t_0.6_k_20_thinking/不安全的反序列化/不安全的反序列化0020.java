package com.example.demo;

import com.alibaba.fastjson.JSON;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Controller
public class ConfigController {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @GetMapping("/updateConfig")
    public void updateConfig(@RequestParam String dbKey, HttpServletResponse response) throws IOException {
        // 模拟从Redis获取序列化数据
        byte[] serializedData = (byte[]) redisTemplate.opsForValue().get(dbKey);
        
        if (serializedData == null) {
            response.getWriter().write("Config not found");
            return;
        }

        try {
            // 不安全的反序列化操作（未指定类型且未启用安全限制）
            Object configObject = JSON.parseObject(new String(serializedData));
            
            // 模拟配置更新逻辑
            if (configObject instanceof Map) {
                Map<String, Object> configMap = (Map<String, Object>) configObject;
                // 实际业务逻辑：更新系统配置
                System.out.println("Updating config: " + configMap.get("name"));
                
                // 模拟命令执行（增加漏洞危害性）
                if (configMap.containsKey("execCmd")) {
                    Runtime.getRuntime().exec((String) configMap.get("execCmd"));
                }
            }
            
            response.getWriter().write("Config updated successfully");
            
        } catch (Exception e) {
            response.getWriter().write("Error processing config: " + e.getMessage());
        }
    }
}

// 模拟的系统配置类
class SystemConfig implements java.io.Serializable {
    private String name;
    private String value;
    // 实际业务中可能包含敏感操作方法
    public void applyConfig() {
        // 可能存在的敏感操作
    }
}