package com.example.taskmanager.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/tasks")
public class TaskController {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @PostMapping("/callback")
    public String handlePaymentCallback(@RequestBody String callbackData) {
        // 模拟支付回调处理流程
        JSONObject jsonObject = JSON.parseObject(callbackData);
        // 存储回调数据到Redis（使用原生序列化）
        redisTemplate.opsForValue().set("callback_data", jsonObject);
        return "Callback processed";
    }

    @GetMapping("/data")
    public String getDdjhData() {
        // 从Redis获取数据并反序列化
        Object data = redisTemplate.opsForValue().get("callback_data");
        if (data instanceof JSONObject) {
            JSONArray dataArray = JSON.parseArray(data.toString());
            return "Data size: " + dataArray.size();
        }
        return "No data";
    }

    @PostMapping("/mock")
    public void mockChange2(@RequestParam String json) {
        // 模拟存在漏洞的反序列化调用
        JSON.parseObject(json, Map.class);
    }

    // 模拟系统配置类
    static class SystemSetting {
        static class AuthProvider {
            static final String GROUP = "configMap";
        }
    }

    // 模拟RedisTemplate配置（原生序列化）
    static class RedisConfig {
        RedisTemplate<String, Object> redisTemplate() {
            RedisTemplate<String, Object> template = new RedisTemplate<>();
            template.setKeySerializer(new org.springframework.data.redis.serializer.StringRedisSerializer());
            template.setValueSerializer(new org.springframework.data.redis.serializer.JdkSerializationRedisSerializer());
            return template;
        }
    }

    public static void main(String[] args) throws IOException {
        // 模拟攻击场景
        String maliciousJson = "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\"," +
                "\\"_bytecodes\\":[\\"fake_bytecode\\"],\\"_name\\":\\"a\\",\\"_tfactory\\":{}}";
        
        // 触发FastJSON反序列化漏洞
        JSON.parseObject(maliciousJson);
    }
}