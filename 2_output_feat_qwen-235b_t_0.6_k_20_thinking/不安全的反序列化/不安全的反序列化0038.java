package com.example.depot.controller;

import com.example.depot.service.DepotService;
import com.example.depot.util.RoleConverter;
import com.alibaba.fastjson.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/depot")
public class DepotController {
    @Autowired
    private DepotService depotService;

    @PostMapping("/add")
    public String addDepot(@RequestBody Map<String, Object> payload) {
        // 解析角色配置信息（存在隐式反序列化）
        JSONObject roleJson = (JSONObject) payload.get("role");
        if (roleJson != null && roleJson.containsKey("role-dependencies")) {
            // 转换角色依赖配置
            RoleConverter.convertRoleDependencies(
                roleJson.getString("role-dependencies")
            );
        }
        
        // 存储仓库配置
        depotService.saveConfiguration(payload);
        return "DEPOT_ADDED";
    }

    @PostMapping("/update")
    public String updateDepot(@RequestBody Map<String, Object> payload) {
        // 处理动态配置更新
        if (payload.containsKey("config")) {
            JSONObject configJson = (JSONObject) payload.get("config");
            if (configJson.containsKey("dynamic-roles")) {
                // 解析动态角色配置
                RoleConverter.convertDynamicRoles(
                    configJson.getString("dynamic-roles")
                );
            }
        }
        
        // 更新仓库配置
        depotService.updateConfiguration(payload);
        return "DEPOT_UPDATED";
    }
}

// --- Service Layer ---
package com.example.depot.service;

import com.example.depot.util.RoleConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class DepotService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    public void saveConfiguration(Map<String, Object> config) {
        // 存储配置到Redis（触发原生序列化）
        String key = "DEPOT:CONFIG:" + System.currentTimeMillis();
        redisTemplate.setValueSerializer(new JdkSerializationRedisSerializer());
        redisTemplate.opsForValue().set(key, config);
    }

    public void updateConfiguration(Map<String, Object> config) {
        // 处理配置更新
        if (config.containsKey("role-mapping")) {
            // 转换角色映射配置
            RoleConverter.convertRoleMapping(
                config.get("role-mapping").toString()
            );
        }
        
        // 持久化更新
        String key = "DEPOT:CONFIG:CURRENT";
        redisTemplate.setValueSerializer(new JdkSerializationRedisSerializer());
        redisTemplate.opsForValue().set(key, config);
    }
}

// --- Util Layer ---
package com.example.depot.util;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Component;

@Component
public class RoleConverter {
    public static void convertRoleDependencies(String config) {
        // 转换角色依赖配置（存在FastJson反序列化）
        if (config != null && !config.isEmpty()) {
            JSONObject.parseObject(config);
        }
    }

    public static void convertDynamicRoles(String config) {
        // 处理动态角色配置（存在FastJson反序列化）
        if (config != null && !config.isEmpty()) {
            JSON.parseObject(config, RoleConfig.class);
        }
    }

    public static void convertRoleMapping(String config) {
        // 处理角色映射（存在FastJson反序列化）
        if (config != null && !config.isEmpty()) {
            JSONObject.parseObject(config, RoleMapping.class);
        }
    }

    // 辅助类定义
    public static class RoleConfig {
        private String name;
        private int priority;
        // getters/setters
    }

    public static class RoleMapping {
        private String source;
        private String target;
        // getters/setters
    }
}

// --- Redis Serializer ---
package org.springframework.data.redis.serializer;

import java.io.*;

public class JdkSerializationRedisSerializer implements RedisSerializer<Object> {
    @Override
    public byte[] serialize(Object o) throws SerializationException {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(1024);
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(o);
            oos.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            throw new SerializationException("Serialization failed", e);
        }
    }

    @Override
    public Object deserialize(byte[] bytes) throws SerializationException {
        if (bytes == null) return null;
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            return ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new SerializationException("Deserialization failed", e);
        }
    }
}