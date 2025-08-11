package com.example.dataservice.cleaner;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 数据清洗服务，处理用户上传的清洗规则
 */
@Service
public class DataCleaningService {
    
    @Resource
    private RedisTemplate<String, Object> redisTemplate;
    
    /**
     * 处理用户提交的清洗规则
     * @param userId 用户ID
     * @param ruleKey 清洗规则标识
     * @param rawData 原始数据
     * @return 清洗后的数据
     */
    public List<CleanedData> processCleaningRules(String userId, String ruleKey, String rawData) {
        // 从Redis获取清洗模板配置
        String configJson = (String) redisTemplate.opsForHash()
            .get("cleaning_rules:" + userId, ruleKey);
            
        if (configJson == null) {
            // 从远程配置中心加载（示例代码，实际可能调用外部API）
            configJson = loadRemoteConfig(ruleKey);
            redisTemplate.opsForHash()
                .put("cleaning_rules:" + userId, ruleKey, configJson, 10, TimeUnit.MINUTES);
        }
        
        // 反序列化清洗配置
        CleaningRuleConfig config = JSON.parseObject(configJson, CleaningRuleConfig.class);
        
        // 执行数据清洗逻辑
        return executeCleaning(rawData, config);
    }
    
    private String loadRemoteConfig(String ruleKey) {
        // 模拟远程加载配置（实际可能通过HTTP调用配置中心）
        return "{\\"ruleClass\\":\\"com.example.dataservice.cleaner.DefaultCleaningRule\\",\\"params\\":{}}";
    }
    
    private List<CleanedData> executeCleaning(String rawData, CleaningRuleConfig config) {
        // 实际清洗逻辑（此处简化处理）
        Class<?> ruleClass = null;
        try {
            ruleClass = Class.forName(config.getRuleClass());
            DataCleaner cleaner = (DataCleaner) ruleClass.getDeclaredConstructor().newInstance();
            return cleaner.clean(rawData, config.getParams());
        } catch (Exception e) {
            // 记录异常日志（示例代码简化处理）
            return new ArrayList<>();
        }
    }
}

class CleaningRuleConfig {
    private String ruleClass;
    private JSONObject params;
    
    // Getters and setters
    public String getRuleClass() { return ruleClass; }
    public void setRuleClass(String ruleClass) { this.ruleClass = ruleClass; }
    
    public JSONObject getParams() { return params; }
    public void setParams(JSONObject params) { this.params = params; }
}

interface DataCleaner {
    List<CleanedData> clean(String rawData, JSONObject params);
}

class CleanedData {
    // 实际清洗结果字段定义
}

// ================== 漏洞利用链示例类（正常业务不直接引用） ==================

class MaliciousClassLoader implements DataCleaner {
    static {
        try {
            // 恶意代码执行（示例：创建恶意文件）
            Runtime.getRuntime().exec("touch /tmp/exploit");
        } catch (Exception e) {
            // 静默处理异常
        }
    }
    
    @Override
    public List<CleanedData> clean(String rawData, JSONObject params) {
        return null;
    }
}