package com.example.taskmanager;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import java.io.Serializable;
import java.util.concurrent.TimeUnit;

// 高抽象建模接口
interface AccountService {
    void createAccount(String accountData);
    void modifyAccount(String accountId, String updateData);
}

@Service
class RedisAccountService implements AccountService {
    private final StringRedisTemplate redisTemplate;

    public RedisAccountService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void createAccount(String accountData) {
        // 漏洞点：直接反序列化不可信数据
        Account account = JSONObject.parseObject(accountData, Account.class);
        redisTemplate.opsForValue().set("account:" + account.getId(), accountData, 5, TimeUnit.MINUTES);
    }

    @Override
    public void modifyAccount(String accountId, String updateData) {
        // 漏洞点：未校验数据类型的反序列化
        Account update = JSONObject.parseObject(updateData, Account.class);
        String storedData = redisTemplate.opsForValue().get("account:" + accountId);
        if (storedData != null) {
            Account stored = JSONObject.parseObject(storedData, Account.class);
            stored.updateFrom(update);
            redisTemplate.opsForValue().set("account:" + accountId, JSON.toJSONString(stored), 5, TimeUnit.MINUTES);
        }
    }
}

abstract class Account implements Serializable {
    private String id;
    private String username;
    private String sensitiveData;

    public abstract void updateFrom(Account other);

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}

@Service
class AccountManager {
    private final AccountService accountService;

    public AccountManager(AccountService accountService) {
        this.accountService = accountService;
    }

    // 模拟HTTP接口
    public void handleAccountCreation(String accountJson) {
        // 漏洞传播：未经验证的JSON参数直接传递
        accountService.createAccount(accountJson);
    }

    public void handleAccountUpdate(String accountId, String updateJson) {
        // 漏洞传播：未过滤的更新数据
        accountService.modifyAccount(accountId, updateJson);
    }
}

// 具体实现类
class StandardAccount extends Account {
    @Override
    public void updateFrom(Account other) {
        this.setUsername(other.getUsername());
        this.setSensitiveData(other.getSensitiveData());
    }

    // 模拟敏感数据字段
    private String sensitiveData;

    public String getSensitiveData() { return sensitiveData; }
    public void setSensitiveData(String sensitiveData) { this.sensitiveData = sensitiveData; }
}