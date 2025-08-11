package com.example.crm.controller;

import com.alibaba.fastjson.JSON;
import com.example.crm.service.ConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/admin/config")
public class AdminController {
    @Autowired
    private ConfigService configService;

    @PostMapping("/mall")
    public String updateMallConfig(@RequestBody String body) {
        // 解析并存储商城配置
        Map<String, Object> config = JSON.parseObject(body);
        configService.processAndStoreConfig(config);
        return "Success";
    }
}

// Redis存储服务
package com.example.crm.service;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class ConfigService {
    private final RedisTemplate<String, Object> redisTemplate;

    public ConfigService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void processAndStoreConfig(Map<String, Object> config) {
        // 转换配置格式并存储
        String serialized = JSON.toJSONString(config);
        mockChange(serialized);
    }

    private void mockChange(String data) {
        // 数据格式转换处理
        String transformed = "CONFIG_DATA:" + data;
        mockChange2(transformed);
    }

    private void mockChange2(String data) {
        // 关键数据解析逻辑
        if (data.startsWith("CONFIG_DATA:")) {
            String jsonData = data.substring(12);
            Map<String, Object> configMap = JSON.parseObject(jsonData);
            redisTemplate.opsForValue().set("CURRENT_CONFIG", configMap, 10);
        }
    }
}