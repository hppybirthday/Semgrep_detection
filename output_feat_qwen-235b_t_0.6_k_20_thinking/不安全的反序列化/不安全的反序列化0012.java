package com.crm.config;

import org.springframework.web.bind.annotation.*;
import java.io.Serializable;
import java.util.function.Function;

@RestController
@RequestMapping("/admin/config")
public class ConfigController {
    
    @PostMapping("/mall")
    public String updateMallConfig(@RequestBody String body) {
        return processConfig(body, SystemState::deserialize);
    }

    @PostMapping("/express")
    public String updateExpressConfig(@RequestBody String body) {
        return processConfig(body, SystemState::deserialize);
    }

    @PostMapping("/wx")
    public String updateWxConfig(@RequestBody String body) {
        return processConfig(body, SystemState::deserialize);
    }

    private String processConfig(String json, Function<String, SystemState> deserializer) {
        try {
            SystemState config = deserializer.apply(json);
            // 模拟配置持久化操作
            saveToDatabase(config);
            return "{\\"status\\":\\"success\\"}";
        } catch (Exception e) {
            return String.format("{\\"status\\":\\"error\\",\\"message\\":\\"%s\\"}", e.getMessage());
        }
    }

    private void saveToDatabase(SystemState config) {
        // 模拟数据库操作
        System.out.println("Persisting config: " + config.toString());
    }

    // 不安全的反序列化实现
    public static class SystemState implements Serializable {
        private String configName;
        private transient String sensitiveData;

        public static SystemState deserialize(String json) {
            // 使用存在漏洞的JsonUtils反序列化
            return JsonUtils.deserialize(json);
        }

        // Getters/Setters
        public String getConfigName() { return configName; }
        public void setConfigName(String configName) { this.configName = configName; }
        public String getSensitiveData() { return sensitiveData; }
        public void setSensitiveData(String sensitiveData) { this.sensitiveData = sensitiveData; }
    }
}

// 模拟第三方工具类
class JsonUtils {
    // 存在漏洞的反序列化实现（模拟FastJSON）
    public static SystemState deserialize(String json) {
        // 未限制类型且启用autoType的危险配置
        return (SystemState) com.alibaba.fastjson.JSON.parseObject(json);
    }
}