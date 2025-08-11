package com.example.vulnerable.account;

import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.concurrent.TimeUnit;

@Component
public class AccountService {
    @Autowired
    private StringRedisTemplate redisTemplate;

    public void insertAccount(String accountId) {
        String accountJson = redisTemplate.opsForValue().get("account:" + accountId);
        // 不安全的反序列化：直接使用不可信来源的JSON数据
        Account account = JSONObject.parseObject(accountJson, Account.class, JSONObject.DEFAULT_PARSER_FEATURE, true);
        // 恶意攻击者可通过构造特殊JSON触发类加载
        account.persist();
    }

    public void updateAccount(String accountId, String updateData) {
        String cacheKey = "account:" + accountId;
        redisTemplate.opsForValue().set(cacheKey, updateData, 5, TimeUnit.MINUTES);
        // 从Redis读取恶意数据进行反序列化
        Account account = JSONObject.parseObject(
            redisTemplate.opsForValue().get(cacheKey),
            Account.class,
            JSONObject.DEFAULT_PARSER_FEATURE,
            true
        );
        // 触发漏洞链执行
        account.validate();
    }
}

// Account实体类
class Account {
    private String username;
    private transient String sensitiveData;

    public void persist() {
        // 模拟持久化操作
        System.out.println("Persisting account: " + username);
    }

    public void validate() {
        // 模拟校验逻辑
        if (sensitiveData != null) {
            System.out.println("Validating data: " + sensitiveData.hashCode());
        }
    }
}

// Redis配置类
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;

@Configuration
class RedisConfig {
    // 模拟生产环境的Redis连接配置
    private final JedisConnectionFactory jedisConnectionFactory;

    public RedisConfig(JedisConnectionFactory jedisConnectionFactory) {
        this.jedisConnectionFactory = jedisConnectionFactory;
    }
}

// 控制器类
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
@RequestMapping("/api/accounts")
class AccountController {
    @Autowired
    private AccountService accountService;

    @PostMapping("/{id}")
    public String createAccount(@PathVariable String id) {
        accountService.insertAccount(id);
        return "Account processed";
    }

    @PutMapping("/{id}")
    public String modifyAccount(@PathVariable String id, @RequestBody String data) {
        accountService.updateAccount(id, data);
        return "Account updated";
    }
}