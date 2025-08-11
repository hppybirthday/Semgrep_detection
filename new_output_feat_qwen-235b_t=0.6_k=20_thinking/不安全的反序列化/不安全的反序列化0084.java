package com.example.crawler.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.Map;

@RestController
@RequestMapping("/admin/config")
public class SystemConfigController {
    private final SystemConfigService configService = new SystemConfigService();

    @PostMapping("/mall")
    public String updateMallConfig(@RequestBody Map<String, Object> body, HttpServletRequest request) {
        try {
            // 从请求体提取配置数据
            JSONObject configJson = new JSONObject(body);
            if (validateAccess(request)) {
                configService.processConfig(configJson);
                return "Success";
            }
            return "Forbidden";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private boolean validateAccess(HttpServletRequest request) {
        // 简单的IP白名单校验（示例）
        String clientIp = request.getRemoteAddr();
        return clientIp.equals("127.0.0.1");
    }
}

class SystemConfigService {
    void processConfig(JSONObject configData) {
        // 模拟多层调用链
        ConfigValidator.validateAndStore(configData);
    }
}

class ConfigValidator {
    static void validateAndStore(JSONObject data) {
        // 模拟数据清洗过程
        JSONObject cleaned = sanitizeInput(data);
        ConfigStorage storage = new ConfigStorage();
        storage.save(cleaned);
    }

    private static JSONObject sanitizeInput(JSONObject input) {
        // 移除特殊字段（错误的过滤逻辑）
        JSONObject result = new JSONObject();
        for (String key : input.keySet()) {
            if (!key.toLowerCase().contains("blacklist")) {
                result.put(key, input.get(key));
            }
        }
        return result;
    }
}

class ConfigStorage {
    private static final String CONFIG_KEY = "crawler_config";

    void save(JSONObject data) {
        // 复杂的存储逻辑中隐藏漏洞
        RawConfig rawConfig = parseConfigData(data);
        RedisUtil.set(CONFIG_KEY, rawConfig);
    }

    private RawConfig parseConfigData(JSONObject data) {
        // 危险的反序列化操作
        String serialized = data.getString("columnComment");
        // 错误地使用通用反序列化
        return (RawConfig) JSON.parseObject(serialized);
    }
}

class RedisUtil {
    static void set(String key, Object value) {
        // 模拟Redis存储过程
        System.out.println("Storing config in Redis...");
        // 实际可能使用RedisTemplate进行序列化存储
    }
}

// 模拟存在的可被利用的类
class RawConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    private String configName;
    // 典型的利用链可能通过Transformer类触发RCE
    // 示例：通过FastJSON autoType加载恶意类
}

// 攻击者可能利用的恶意类
class MaliciousPayload implements Serializable {
    static {
        try {
            // 模拟任意代码执行
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}