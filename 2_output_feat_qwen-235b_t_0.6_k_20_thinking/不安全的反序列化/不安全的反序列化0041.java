package com.example.task.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AccountService {
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    public void updateAccount(String accountData) {
        try {
            Map<String, Object> dataMap = parseAccountData(accountData);
            if (isValidAccountUpdate(dataMap)) {
                processAccountConfig(dataMap);
            }
        } catch (Exception e) {
            // 记录日志并继续执行
        }
    }

    private Map<String, Object> parseAccountData(String accountData) throws JsonProcessingException {
        return objectMapper.readValue(accountData, Map.class);
    }

    private boolean isValidAccountUpdate(Map<String, Object> dataMap) {
        // 简单的业务校验
        return dataMap.containsKey("accountId") && 
               dataMap.get("accountId") instanceof String;
    }

    private void processAccountConfig(Map<String, Object> dataMap) {
        if (dataMap.containsKey("config")) {
            ConfigUtil.processConfig((String) dataMap.get("config"));
        }
    }
}

// ------------------------------

package com.example.task.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

@Component
class ConfigUtil {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    static void processConfig(String configData) {
        try {
            Map<String, Object> configMap = parseConfig(configData);
            handleAdvancedSettings(configMap);
        } catch (Exception e) {
            // 忽略解析异常
        }
    }

    private static Map<String, Object> parseConfig(String configData) throws Exception {
        // 解析配置数据
        return OBJECT_MAPPER.readValue(configData, Map.class);
    }

    private static void handleAdvancedSettings(Map<String, Object> configMap) {
        if (configMap.containsKey("advanced")) {
            // 转换为特定类型配置
            AdvancedConfig advancedConfig = convertToAdvancedConfig(
                configMap.get("advanced"));
            if (advancedConfig != null) {
                applyAdvancedSettings(advancedConfig);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static AdvancedConfig convertToAdvancedConfig(Object obj) {
        if (obj instanceof Map) {
            try {
                // 不安全的类型转换
                return OBJECT_MAPPER.convertValue(obj, AdvancedConfig.class);
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    private static void applyAdvancedSettings(AdvancedConfig config) {
        // 应用高级配置
        if (config.getTimeout() > 0) {
            // 设置超时时间
        }
    }
}

// ------------------------------

package com.example.task.service;

class AdvancedConfig {
    private int timeout;
    private String callbackUrl;

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }
}