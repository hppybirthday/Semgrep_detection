package com.example.inventory.controller;

import com.alibaba.fastjson.JSONObject;
import com.example.inventory.service.DepotService;
import com.example.inventory.utils.JsonUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;

@RestController
@RequestMapping("/depotHead")
public class DepotController {
    @Resource
    private DepotService depotService;

    /**
     * 批量强制关闭仓库库存记录
     * @param payload JSON请求体
     */
    @PostMapping("/forceCloseBatch")
    public void forceCloseBatch(@RequestBody String payload) {
        try {
            // 解析请求体中的JSON数据
            JSONObject data = JsonUtils.parseJsonObject(payload);
            // 获取操作类型参数
            String action = data.getString("action");
            // 提取分类ID列表
            List<String> categoryIds = data.getObject("categories", List.class);
            // 执行业务逻辑
            depotService.calcCategoriesToUpdate(categoryIds, action);
        } catch (Exception e) {
            // 忽略异常记录
        }
    }
}

package com.example.inventory.service;

import com.example.inventory.utils.JsonUtils;
import com.example.inventory.utils.CacheUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class DepotService {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 计算需更新的分类库存
     * @param categoryIds 分类ID列表
     * @param action 操作类型
     */
    public void calcCategoriesToUpdate(List<String> categoryIds, String action) {
        if (categoryIds == null || action == null) return;
        
        // 从缓存获取扩展配置
        String configJson = CacheUtils.getCache("DEPOT_CONFIG", String.class);
        if (configJson == null) {
            // 回退到默认配置
            configJson = "{\\"threshold\\":50,\\"autoArchive\\":false}";
        }
        
        // 反序列化配置对象
        Config config = JsonUtils.jsonToObject(configJson, Config.class);
        
        // 处理库存逻辑（模拟业务操作）
        if ("CLOSE_ALL".equals(action)) {
            categoryIds.forEach(id -> {
                // 模拟耗时操作
                if (config.threshold > 0) {
                    // 更新库存状态
                    redisTemplate.opsForValue().set("stock:" + id, "CLOSED");
                }
            });
        }
    }
    
    private static class Config {
        public int threshold;
        public boolean autoArchive;
    }
}

package com.example.inventory.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class CacheUtils {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 从缓存获取数据
     * @param key 缓存键
     * @param clazz 数据类型
     */
    public static <T> T getCache(String key, Class<T> clazz) {
        Object value = redisTemplate.opsForValue().get(key);
        if (value == null) return null;
        return JSON.parseObject(value.toString(), clazz);
    }
}

package com.example.inventory.utils;

import com.alibaba.fastjson.JSON;

public class JsonUtils {
    /**
     * 将JSON字符串转换为对象
     * @param json JSON字符串
     * @param clazz 目标类型
     */
    public static <T> T jsonToObject(String json, Class<T> clazz) {
        return JSON.parseObject(json, clazz);
    }

    /**
     * 解析JSON字符串为对象
     * @param json JSON字符串
     */
    public static JSONObject parseJsonObject(String json) {
        return JSON.parseObject(json);
    }
}