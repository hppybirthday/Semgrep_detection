package com.mathsim.model.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.mathsim.model.service.SimulationService;
import com.mathsim.model.entity.ModelConfig;
import com.mathsim.model.redis.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/simulation")
public class SimulationController {
    
    @Autowired
    private SimulationService simulationService;

    @Autowired
    private RedisCache redisCache;

    /**
     * 数学模型配置更新接口
     * 攻击者可通过columnComment参数注入恶意JSON
     */
    @PostMapping("/config/update")
    public String updateModelConfig(@RequestBody Map<String, Object> configMap, HttpServletRequest request) {
        try {
            // 从请求头获取UUID用于Redis查询
            String uuid = request.getHeader("X-Model-UUID");
            if (uuid == null || uuid.isEmpty()) {
                return "Missing UUID header";
            }

            // 从Redis获取原始数据包（模拟中间缓存环节）
            String rawPacket = redisCache.get(uuid);
            if (rawPacket == null || rawPacket.isEmpty()) {
                return "No cached data found";
            }

            // 二次解析原始数据包（第一层反序列化）
            Map<String, Object> packetMap = JSON.parseObject(rawPacket, Map.class);
            
            // 从攻击者可控的columnComment参数注入恶意JSON
            String columnComment = (String) configMap.get("columnComment");
            if (columnComment != null && !columnComment.isEmpty()) {
                packetMap.put("metadata", columnComment);
            }

            // 关键漏洞点：未经类型限制的反序列化操作
            processMetadata(packetMap);
            
            // 业务逻辑继续执行（分散注意力）
            simulationService.validateConfig(configMap);
            return "Configuration updated successfully";
            
        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }

    /**
     * 模拟复杂调用链中的反序列化操作
     * 攻击路径：Redis数据 -> 本地处理 -> 二次反序列化
     */
    private void processMetadata(Map<String, Object> packetMap) {
        // 从Redis数据中提取攻击者注入的payload
        Object metadata = packetMap.get("metadata");
        if (metadata instanceof String) {
            String metadataStr = (String) metadata;
            
            // 致命漏洞：使用不安全的反序列化方式
            // 攻击者可通过特殊构造的JSON字符串触发任意代码执行
            Object parsed = JSON.parse(metadataStr);
            
            // 模拟后续业务处理（进一步隐藏漏洞）
            if (parsed instanceof JSONArray) {
                handleArray((JSONArray) parsed);
            }
        }
    }

    /**
     * 处理数组类型的元数据
     * 攻击载荷可能在此阶段触发
     */
    private void handleArray(JSONArray array) {
        for (Object item : array) {
            if (item instanceof Map) {
                // 模拟业务逻辑：提取模型参数
                Map<String, Object> param = (Map<String, Object>) item;
                simulationService.processParameter(param);
            }
        }
    }

    // 模拟其他业务方法
    @GetMapping("/config/sample")
    public ModelConfig getSampleConfig() {
        return simulationService.getSampleConfiguration();
    }
}

// --- 业务服务类 ---
package com.mathsim.model.service;

import com.mathsim.model.entity.ModelConfig;
import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class SimulationService {
    
    public void validateConfig(Map<String, Object> configMap) {
        // 模拟配置验证逻辑
        if (configMap.containsKey("modelName")) {
            String modelName = (String) configMap.get("modelName");
            if (modelName.length() < 3) {
                throw new IllegalArgumentException("Model name too short");
            }
        }
    }

    public ModelConfig getSampleConfiguration() {
        ModelConfig config = new ModelConfig();
        config.setModelName("DefaultModel");
        config.setPrecision(0.001f);
        return config;
    }

    public void processParameter(Map<String, Object> param) {
        // 模拟参数处理
        if (param.containsKey("type")) {
            String type = (String) param.get("type");
            if (type.equals("dynamic")) {
                // 这里可能触发攻击载荷
                JSONObject.parseObject(param.toString());
            }
        }
    }
}

// --- Redis缓存类 ---
package com.mathsim.model.redis;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class RedisCache {
    
    @Resource
    private StringRedisTemplate redisTemplate;

    public String get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    public void set(String key, String value) {
        redisTemplate.opsForValue().set(key, value);
    }
}