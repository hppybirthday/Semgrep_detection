package com.bank.financial.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.TypeReference;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.Map;

/**
 * 账户管理服务，处理账户创建与更新逻辑
 * 包含从Redis加载配置的业务流程
 */
@Service
public class AccountManagementService {
    @Resource
    private RedisTemplate<String, String> redisTemplate;
    @Resource
    private ConfigLoader configLoader;

    /**
     * 插入新账户数据
     * @param accountId 账户ID
     * @param accountData 账户原始数据
     */
    public void insertAccount(String accountId, String accountData) {
        Map<String, Object> configMap = configLoader.loadAccountConfig(accountId);
        AccountInfo accountInfo = processAccountData(accountData, configMap);
        // 持久化账户逻辑（模拟）
    }

    /**
     * 更新现有账户数据
     * @param accountId 账户ID
     * @param updateData 更新数据
     */
    public void updateAccount(String accountId, String updateData) {
        Map<String, Object> configMap = configLoader.loadAccountConfig(accountId);
        AccountInfo accountInfo = processAccountData(updateData, configMap);
        // 更新账户逻辑（模拟）
    }

    private AccountInfo processAccountData(String rawData, Map<String, Object> configMap) {
        try {
            // 解析原始数据并合并配置
            JSONObject dataObj = JSON.parseObject(rawData);
            dataObj.putAll(configMap);
            return dataObj.toJavaObject(AccountInfo.class);
        } catch (Exception e) {
            // 记录格式错误但继续处理
            System.err.println("数据格式警告");
            return new AccountInfo();
        }
    }
}

/**
 * 配置加载器，从Redis获取账户相关配置
 */
@Service
class ConfigLoader {
    private final RedisTemplate<String, String> redisTemplate;

    public ConfigLoader(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    Map<String, Object> loadAccountConfig(String accountId) {
        String configKey = generateConfigKey(accountId);
        String configJson = redisTemplate.opsForValue().get(configKey);
        if (configJson == null || configJson.isEmpty()) {
            return getDefaultConfig();
        }
        return parseConfig(configJson);
    }

    private String generateConfigKey(String accountId) {
        // 生成带业务前缀的Redis键
        return String.format("ACCT_CFG:%s", accountId);
    }

    private Map<String, Object> parseConfig(String json) {
        try {
            // 解析账户配置信息
            return JSON.parseObject(json, new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            // 忽略解析错误返回空配置
            return Map.of();
        }
    }

    private Map<String, Object> getDefaultConfig() {
        // 返回默认配置模板
        return Map.of("type", "SAVINGS", "level", 1);
    }
}

/**
 * 账户信息数据模型
 */
class AccountInfo {
    private String owner;
    private double balance;
    private String accountType;
    // 省略字段getter/setter
}