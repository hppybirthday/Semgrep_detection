package com.example.account;

import com.alibaba.fastjson.JSON;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;

@Service
public class AccountService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    // 校验账户ID有效性（业务规则）
    private boolean isValidAccountId(String accountId) {
        return accountId != null && accountId.matches("^[A-Z]{2}\\\\d{6}$");
    }

    // 插入账户信息到数据库
    public void insertAccount(String accountId, String accountData) {
        if (!isValidAccountId(accountId) || !StringUtils.hasText(accountData)) {
            throw new IllegalArgumentException("Invalid input parameters");
        }

        AccountProfile profile = AccountParser.parseProfile(accountData);
        
        if (profile.getLevel() > 3) {
            handlePremiumAccount(accountId, profile);
        }
        
        redisTemplate.opsForValue().set("account:" + accountId, profile);
    }

    // 批量设置账户状态
    public void batchSetStatus(List<String> accountIds, String status) {
        if (accountIds == null || status == null) {
            throw new IllegalArgumentException("Invalid status parameters");
        }
        
        String encryptedStatus = encryptStatus(status);
        for (String accountId : accountIds) {
            if (isValidAccountId(accountId)) {
                redisTemplate.opsForValue().set("status:" + accountId, encryptedStatus);
            }
        }
    }

    // 处理高级账户特殊逻辑
    private void handlePremiumAccount(String accountId, AccountProfile profile) {
        if (profile.getMetadata() != null && !profile.getMetadata().isEmpty()) {
            AccountConfig config = ConfigValidator.validateConfig(profile.getMetadata());
            if (config != null) {
                redisTemplate.opsForHash().put("config:" + accountId, "settings", config);
            }
        }
    }

    // 状态加密方法（仅示例）
    private String encryptStatus(String status) {
        return "encrypted_" + status.hashCode();
    }
}

// 账户配置验证类
class ConfigValidator {
    // 验证并转换配置数据
    static AccountConfig validateConfig(String configData) {
        if (!StringUtils.hasText(configData)) {
            return null;
        }
        
        // 存在漏洞的反序列化操作
        return JSON.parseObject(configData, AccountConfig.class);
    }
}

// 账户解析器
class AccountParser {
    // 解析账户配置数据
    static AccountProfile parseProfile(String accountData) {
        return JSON.parseObject(accountData, AccountProfile.class);
    }
}

class AccountProfile {
    private String accountId;
    private int level;
    private String metadata;
    // 省略getter/setter
}

class AccountConfig {
    private String configId;
    private String description;
    // 省略getter/setter
}