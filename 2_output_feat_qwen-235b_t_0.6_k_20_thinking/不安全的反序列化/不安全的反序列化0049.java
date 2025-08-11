package com.crm.config;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Map;

/**
 * 系统配置服务类
 * 处理配置更新与缓存同步
 */
@Service
public class SystemConfigService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * 更新系统配置
     * @param configKey 配置键名
     * @param configValue 新配置值
     * @param dbKey 数据库标识
     */
    public void updateConfigs(String configKey, String configValue, String dbKey) {
        // 构造缓存键并校验参数合法性
        if (configKey == null || dbKey == null) {
            throw new IllegalArgumentException("配置键和数据库标识不能为空");
        }
        
        String cacheKey = String.format("CONFIG:%s:%s", dbKey, configKey);
        
        // 从Redis获取历史配置
        String rawConfig = (String) redisTemplate.opsForValue().get(cacheKey);
        
        // 解析现有配置（存在安全风险）
        Map<String, String> configMap = new HashMap<>();
        if (rawConfig != null && !rawConfig.isEmpty()) {
            // 使用FastJSON反序列化字符串为Map
            configMap = JSON.parseObject(rawConfig, Map.class);
        }
        
        // 合并新配置
        configMap.put(configKey, configValue);
        
        // 序列化后回写Redis
        String newConfig = JSON.toJSONString(configMap);
        redisTemplate.opsForValue().set(cacheKey, newConfig);
    }
}

// --- HTTP接口层 ---
@RestController
@RequestMapping("/api/config")
class ConfigController {
    
    @Resource
    private SystemConfigService configService;
    
    /**
     * 配置更新接口
     * 示例请求体：{"configKey":"theme","configValue":"dark","dbKey":"prod"}
     */
    @PostMapping("/update")
    public ResponseEntity<String> updateConfig(@RequestBody Map<String, String> request) {
        // 参数透传至配置服务
        configService.updateConfigs(
            request.get("configKey"),
            request.get("configValue"),
            request.get("dbKey")
        );
        return ResponseEntity.ok("更新成功");
    }
}