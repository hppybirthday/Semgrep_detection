package com.example.demo;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class VulnerableController {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    // 模拟存在漏洞的配置对象
    public static class ConfigMap {
        private Map<String, Object> data; // 危险的Object类型
        
        public Map<String, Object> getData() {
            return data;
        }
            
        public void setData(Map<String, Object> data) {
            this.data = data;
        }
    }
    
    // 危险的反序列化入口点1：Spring自动反序列化
    @PostMapping("/config")
    public String saveConfig(@RequestBody ConfigMap configMap) {
        // 攻击者可通过构造特殊@type字段控制反序列化类型
        String sensitiveData = configMap.getData().get("secret").toString();
        return "Config saved: " + sensitiveData;
    }
    
    // 危险的反序列化入口点2：FastJSON手动解析
    @GetMapping("/parse")
    public String mockChange2(@RequestParam String jsonData) {
        // 未指定目标类类型，存在类型自动识别漏洞
        Object obj = JSON.parseObject(jsonData); // Noncompliant
        return "Parsed: " + obj.getClass().getName();
    }
    
    // 危险的反序列化入口点3：FastJSON数组解析
    public List<?> getDdjhData(String jsonArray) {
        // 未限制集合元素类型
        return JSON.parseArray(jsonArray); // Noncompliant
    }
    
    // 模拟业务方法中Redis数据反序列化
    public void processRedisData(String key) throws IOException {
        Object rawData = redisTemplate.opsForValue().get(key);
        if (rawData instanceof String) {
            // 危险的反序列化操作
            JSON.parseObject((String)rawData); // Noncompliant
        }
    }
    
    // 恶意payload示例：
    // {"@type":"java.lang.ProcessBuilder","command":["calc"]}
    // 或使用Jackson多态类型：{"@class":"com.example.MaliciousClass"...}
}