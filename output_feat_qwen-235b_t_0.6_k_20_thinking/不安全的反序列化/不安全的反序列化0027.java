package com.bank.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/configure")
    public String updateUserConfiguration(@RequestParam String classData) {
        try {
            // 漏洞点：直接反序列化不可信数据
            Object config = JSON.parseObject(classData, Object.class);
            
            // 模拟业务处理
            if (config instanceof Map) {
                String userId = (String) ((Map)config).get("userId");
                String currency = (String) ((Map)config).get("preferredCurrency");
                boolean notifications = (Boolean) ((Map)config).get("enableNotifications");
                
                userService.saveConfiguration(
                    new UserConfiguration(userId, currency, notifications)
                );
                return "Configuration updated";
            }
            return "Invalid configuration format";
        } catch (Exception e) {
            return "Error processing configuration: " + e.getMessage();
        }
    }
}

// 领域实体
class UserConfiguration {
    private final String userId;
    private final String preferredCurrency;
    private final boolean enableNotifications;

    public UserConfiguration(String userId, String preferredCurrency, boolean enableNotifications) {
        this.userId = userId;
        this.preferredCurrency = preferredCurrency;
        this.enableNotifications = enableNotifications;
    }

    // Getters and domain methods
}

// 应用服务
class UserService {
    void saveConfiguration(UserConfiguration config) {
        // 持久化逻辑（漏洞触发点在此前）
    }
}