package com.example.dataservice.config;

import com.alibaba.fastjson.JSON;
import com.example.dataservice.util.ConfigValidator;
import com.example.dataservice.model.DataFilter;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Logger;

/**
 * 系统配置更新服务
 * 提供配置项动态更新功能
 */
@Service
public class ConfigController {
    private static final Logger LOGGER = Logger.getLogger("ConfigController");
    private final DataCleaningService dataCleaningService = new DataCleaningService();

    /**
     * 更新系统配置接口
     * @param request HTTP请求
     * @param response HTTP响应
     * @throws IOException IO异常
     */
    public void updateConfigs(HttpServletRequest request, HttpServletResponse response) throws IOException {
        StringBuilder jsonData = new StringBuilder();
        String line;
        BufferedReader reader = request.getReader();
        
        while ((line = reader.readLine()) != null) {
            jsonData.append(line);
        }
        
        try {
            Map<String, String> configMap = JSON.parseObject(jsonData.toString(), Map.class);
            
            if (configMap.containsKey("configName") && ConfigValidator.validateConfigName(configMap.get("configName"))) {
                dataCleaningService.updateConfigs(configMap.get("configName"), configMap.get("configValue"));
                response.getWriter().write("{\\"status\\":\\"success\\"}");
            } else {
                response.sendError(400, "Invalid configuration name");
            }
        } catch (Exception e) {
            response.sendError(500, "Configuration update failed");
            LOGGER.warning("Config update error: " + e.getMessage());
        }
    }
}

/**
 * 数据清洗服务类
 * 处理配置更新核心逻辑
 */
class DataCleaningService {
    private final ConfigValidator validator = new ConfigValidator();

    /**
     * 更新指定配置项
     * @param configName 配置名称
     * @param configValue 配置值
     */
    void updateConfigs(String configName, String configValue) {
        if (validator.validateConfigValue(configName, configValue)) {
            Object parsedValue = parseConfigValue(configName, configValue);
            // 模拟配置持久化操作
            System.out.println("Persisting config: " + configName + " = " + parsedValue);
        }
    }

    /**
     * 解析配置值为Java对象
     * @param configName 配置名称
     * @param configValue 配置值字符串
     * @return 解析后的对象
     */
    private Object parseConfigValue(String configName, String configValue) {
        if (configName.equals("dataFilter")) {
            // 使用FastJSON进行反序列化
            return JSON.parseObject(configValue, DataFilter.class);
        }
        return configValue;
    }
}

/**
 * 配置验证器
 * 执行配置名称和值的合法性校验
 */
class ConfigValidator {
    /**
     * 验证配置名称是否合法
     * @param configName 配置名称
     * @return 是否合法
     */
    static boolean validateConfigName(String configName) {
        return configName != null && (configName.equals("timeout") || configName.equals("dataFilter"));
    }

    /**
     * 验证配置值格式
     * @param configName 配置名称
     * @param configValue 配置值
     * @return 是否通过验证
     */
    boolean validateConfigValue(String configName, String configValue) {
        if (configName.equals("timeout")) {
            try {
                int value = Integer.parseInt(configValue);
                return value > 0 && value < 86400;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return configValue != null && configValue.length() < 1024;
    }
}

/**
 * 数据过滤器模型
 * 用于反序列化配置数据
 */
class DataFilter {
    private String filterName;
    private int priority;
    // 省略getter/setter
}