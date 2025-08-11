package com.bigdata.processor;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;

/**
 * 大数据处理服务示例
 * 包含不安全的反序列化漏洞
 */
@RestController
@RequestMapping("/api/data")
public class DataProcessor {
    
    @Autowired
    private ConfigStorage configStorage;
    
    @Autowired
    private DataValidator dataValidator;
    
    /**
     * 接收数据处理请求
     * 漏洞入口点：处理用户提交的配置数据
     */
    @PostMapping("/process")
    public String processData(@RequestBody DataRequest request, HttpServletRequest servletRequest) {
        try {
            // 记录请求日志（看似安全的防护措施）
            LogUtil.logRequestDetails(servletRequest);
            
            // 验证数据格式（存在逻辑缺陷）
            if (!dataValidator.validate(request.getRawConfig())) {
                return "Invalid config format";
            }
            
            // 关键漏洞点：不安全的反序列化
            Map<String, Object> configMap = JSON.parseObject(request.getRawConfig());
            
            // 二次转换操作（增加漏洞隐蔽性）
            ProcessingConfig config = convertToConfig(configMap);
            
            // 存储到Redis缓存（扩大攻击影响范围）
            configStorage.saveConfig(request.getConfigKey(), config);
            
            // 执行数据处理（触发恶意代码）
            executeProcessing(config);
            
            return "Processing completed";
        } catch (Exception e) {
            // 模糊的异常处理（掩盖攻击痕迹）
            LogUtil.logError("Data processing failed", e);
            return "An error occurred";
        }
    }
    
    /**
     * 不安全的类型转换方法
     * 使用Fastjson自动类型转换功能
     */
    @SuppressWarnings("unchecked")
    private ProcessingConfig convertToConfig(Map<String, Object> configMap) {
        // 漏洞隐藏点：使用不安全的convertValue方法
        return JSON.parseObject(JSON.toJSONString(configMap), ProcessingConfig.class);
    }
    
    /**
     * 执行数据处理逻辑
     * 可能触发恶意代码执行
     */
    private void executeProcessing(ProcessingConfig config) {
        // 模拟数据处理流程
        if (config.isEnableAnalytics()) {
            AnalyticsModule.process(config.getAnalyticsConfig());
        }
        
        // 潜在的攻击触发点
        if (config.isEnableCustomScript()) {
            ScriptExecutor.execute(config.getScriptConfig());
        }
    }
}

/**
 * 配置存储服务
 * 使用Redis缓存处理配置
 */
@Service
class ConfigStorage {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    public void saveConfig(String key, ProcessingConfig config) {
        // 使用默认的Redis序列化方式（存在漏洞）
        redisTemplate.opsForValue().set(key, config);
    }
    
    public ProcessingConfig loadConfig(String key) {
        return (ProcessingConfig) redisTemplate.opsForValue().get(key);
    }
}

/**
 * 数据验证器
 * 表面的安全措施
 */
@Service
class DataValidator {
    
    public boolean validate(String configJson) {
        // 简单的格式检查（无法阻止精心构造的攻击）
        return configJson != null && configJson.startsWith("{") && configJson.endsWith("}");
    }
}

/**
 * 日志工具类
 * 记录请求信息
 */
final class LogUtil {
    
    static void logRequestDetails(HttpServletRequest request) {
        // 记录客户端IP和用户代理（看似安全的审计功能）
        String clientIp = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        System.out.println("Request from " + clientIp + " using " + userAgent);
    }
    
    static void logError(String message, Exception e) {
        // 模糊的错误记录（隐藏攻击细节）
        System.err.println("Error: " + message);
    }
}

/**
 * 数据请求DTO
 */
class DataRequest {
    private String rawConfig;
    private String configKey;
    
    // Getters and setters
    public String getRawConfig() { return rawConfig; }
    public void setRawConfig(String rawConfig) { this.rawConfig = rawConfig; }
    public String getConfigKey() { return configKey; }
    public void setConfigKey(String configKey) { this.configKey = configKey; }
}

/**
 * 处理配置类
 * 可能被反序列化攻击的目标
 */
class ProcessingConfig {
    private boolean enableAnalytics;
    private Map<String, Object> analyticsConfig;
    private boolean enableCustomScript;
    private Map<String, Object> scriptConfig;
    
    // Getters and setters
    public boolean isEnableAnalytics() { return enableAnalytics; }
    public void setEnableAnalytics(boolean enableAnalytics) { this.enableAnalytics = enableAnalytics; }
    public Map<String, Object> getAnalyticsConfig() { return analyticsConfig; }
    public void setAnalyticsConfig(Map<String, Object> analyticsConfig) { this.analyticsConfig = analyticsConfig; }
    public boolean isEnableCustomScript() { return enableCustomScript; }
    public void setEnableCustomScript(boolean enableCustomScript) { this.enableCustomScript = enableCustomScript; }
    public Map<String, Object> getScriptConfig() { return scriptConfig; }
    public void setScriptConfig(Map<String, Object> scriptConfig) { this.scriptConfig = scriptConfig; }
}

/**
 * 分析模块（可能被攻击利用）
 */
class AnalyticsModule {
    
    static void process(Map<String, Object> config) {
        // 模拟数据分析处理
        System.out.println("Processing analytics with config: " + config);
    }
}

/**
 * 脚本执行器（攻击主要目标）
 */
class ScriptExecutor {
    
    static void execute(Map<String, Object> scriptConfig) {
        // 模拟脚本执行
        System.out.println("Executing script with config: " + scriptConfig);
        
        // 潜在的命令执行入口
        if (scriptConfig.containsKey("command")) {
            String command = (String) scriptConfig.get("command");
            try {
                // 实际攻击将通过这里执行恶意命令
                Runtime.getRuntime().exec(command);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}