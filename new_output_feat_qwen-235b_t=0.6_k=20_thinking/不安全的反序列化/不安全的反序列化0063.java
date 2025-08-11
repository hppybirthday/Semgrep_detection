package com.bank.financial.account;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.math.BigDecimal;
import java.util.concurrent.TimeUnit;

/**
 * 账户服务类
 * @author bank-dev-2023
 */
@Service
public class AccountService {
    @Resource
    private AccountRepository accountRepository;
    
    @Resource
    private AccountRedisCache accountRedisCache;
    
    private static final String ACCOUNT_PREFIX = "ACCT_";
    private static final int CACHE_EXPIRE_HOURS = 2;

    /**
     * 插入新账户信息
     */
    public boolean insertAccount(String accountJson) {
        AccountInfo account = JSON.parseObject(accountJson, AccountInfo.class);
        
        if (!validateAccount(account)) {
            return false;
        }
        
        // 生成账户配置
        AccountConfig config = generateDefaultConfig(account.getUserId());
        account.setConfig(config);
        
        // 存储到数据库
        boolean result = accountRepository.save(account);
        
        // 更新缓存
        if (result) {
            accountRedisCache.updateAccountCache(account.getUserId(), accountJson);
        }
        
        return result;
    }

    /**
     * 生成默认账户配置
     */
    private AccountConfig generateDefaultConfig(Long userId) {
        AccountConfig config = new AccountConfig();
        config.setOwnerId(userId);
        config.setMaxTransferAmount(new BigDecimal("500000.00"));
        config.setNotificationEnabled(true);
        return config;
    }

    /**
     * 验证账户信息
     */
    private boolean validateAccount(AccountInfo account) {
        return account != null && 
               account.getUserId() != null && 
               account.getBalance() != null &&
               account.getBalance().compareTo(BigDecimal.ZERO) >= 0;
    }

    /**
     * 更新账户信息
     */
    public boolean updateAccount(Long userId) {
        String cachedData = accountRedisCache.getAccountData(userId);
        if (cachedData == null) {
            return false;
        }
        
        AccountInfo account = JSON.parseObject(cachedData, AccountInfo.class);
        AccountConfig config = accountRedisCache.getAccountConfig(userId);
        
        if (config == null) {
            return false;
        }
        
        account.setConfig(config);
        return accountRepository.update(account);
    }

    /**
     * 批量设置账户状态
     */
    public boolean batchSetStatus(String accountIds, boolean active) {
        List<Long> ids = parseAccountIds(accountIds);
        if (ids.isEmpty()) {
            return false;
        }
        
        return accountRepository.batchUpdateStatus(ids, active);
    }

    /**
     * 解析账户ID列表
     */
    private List<Long> parseAccountIds(String accountIds) {
        return Arrays.stream(accountIds.split(","))
                     .map(Long::valueOf)
                     .toList();
    }
}

/**
 * Redis缓存服务
 */
@Service
class AccountRedisCache {
    @Resource
    private RedisTemplate<String, String> redisTemplate;

    /**
     * 获取账户配置信息
     */
    public AccountConfig getAccountConfig(Long userId) {
        String key = buildConfigKey(userId);
        String configJson = redisTemplate.opsForValue().get(key);
        
        if (configJson == null) {
            return null;
        }
        
        // 漏洞点：不安全的反序列化
        return JSON.parseObject(configJson, AccountConfig.class, Feature.SupportAutoType);
    }

    /**
     * 存储账户数据
     */
    public void updateAccountCache(Long userId, String accountData) {
        String key = buildAccountKey(userId);
        redisTemplate.opsForValue().set(key, accountData, CACHE_EXPIRE_HOURS, TimeUnit.HOURS);
    }

    /**
     * 获取原始账户数据
     */
    public String getAccountData(Long userId) {
        String key = buildAccountKey(userId);
        return redisTemplate.opsForValue().get(key);
    }

    private String buildAccountKey(Long userId) {
        return ACCOUNT_PREFIX + "DATA_" + userId;
    }

    private String buildConfigKey(Long userId) {
        return ACCOUNT_PREFIX + "CFG_" + userId;
    }
}

/**
 * 账户配置类
 */
class AccountConfig {
    private Long ownerId;
    private BigDecimal maxTransferAmount;
    private boolean notificationEnabled;
    
    // FastJSON反序列化需要默认构造函数
    public AccountConfig() {}

    // Getters and setters
    public Long getOwnerId() { return ownerId; }
    public void setOwnerId(Long ownerId) { this.ownerId = ownerId; }
    
    public BigDecimal getMaxTransferAmount() { return maxTransferAmount; }
    public void setMaxTransferAmount(BigDecimal maxTransferAmount) { 
        this.maxTransferAmount = maxTransferAmount; 
    }
    
    public boolean isNotificationEnabled() { return notificationEnabled; }
    public void setNotificationEnabled(boolean notificationEnabled) { 
        this.notificationEnabled = notificationEnabled; 
    }
}

/**
 * 账户信息类
 */
class AccountInfo {
    private Long userId;
    private String accountNumber;
    private BigDecimal balance;
    private AccountConfig config;
    
    public AccountInfo() {}

    // Getters and setters
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    
    public String getAccountNumber() { return accountNumber; }
    public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }
    
    public BigDecimal getBalance() { return balance; }
    public void setBalance(BigDecimal balance) { this.balance = balance; }
    
    public AccountConfig getConfig() { return config; }
    public void setConfig(AccountConfig config) { this.config = config; }
}