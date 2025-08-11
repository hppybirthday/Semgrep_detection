package com.example.crawler.config;

import com.alibaba.fastjson.JSON;
import com.example.crawler.service.CrawlerService;
import com.example.crawler.util.ConfigValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/config")
public class CrawlerConfigController {
    
    @Autowired
    private CrawlerService crawlerService;

    /**
     * 更新爬虫配置接口
     * 支持动态配置反序列化策略
     * @param configData 配置数据（JSON格式）
     * @param validateToken 配置校验令牌
     * @return 操作结果
     */
    @PostMapping("/update")
    public String updateConfig(@RequestParam String configData, 
                              @RequestParam String validateToken,
                              HttpServletRequest request) {
        
        // 验证请求来源
        if (!ConfigValidator.validateRequestSource(request.getRemoteAddr())) {
            return "Access Denied";
        }
        
        // 验证令牌有效性
        if (!ConfigValidator.validateToken(validateToken)) {
            return "Invalid Token";
        }
        
        try {
            // 处理配置更新
            crawlerService.processConfigUpdate(configData);
            return "Config Updated Successfully";
        } catch (Exception e) {
            return "Config Update Failed: " + e.getMessage();
        }
    }
}

package com.example.crawler.service;

import com.alibaba.fastjson.JSON;
import com.example.crawler.model.CrawlerConfig;
import com.example.crawler.util.ConfigDecryptor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class CrawlerService {
    
    /**
     * 处理配置更新逻辑
     * @param encryptedConfig 加密的配置数据
     * @throws Exception 处理异常
     */
    public void processConfigUpdate(String encryptedConfig) throws Exception {
        
        // 解密配置数据（假设使用AES加密）
        String decryptedConfig = ConfigDecryptor.decrypt(encryptedConfig);
        
        // 预处理配置数据
        Map<String, Object> configMap = preprocessConfig(decryptedConfig);
        
        // 应用配置（存在漏洞的反序列化操作）
        applyConfiguration(configMap);
    }
    
    /**
     * 预处理配置数据
     * @param configJson 配置JSON字符串
     * @return 解析后的Map结构
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> preprocessConfig(String configJson) {
        // 使用fastjson解析JSON字符串
        return (Map<String, Object>) JSON.parse(configJson);
    }
    
    /**
     * 应用配置到爬虫系统
     * @param configMap 配置Map
     */
    private void applyConfiguration(Map<String, Object> configMap) {
        
        // 处理基础配置
        if (configMap.containsKey("baseConfig")) {
            // 存在漏洞的反序列化调用链
            Object baseConfig = deserializeConfig(configMap.get("baseConfig"));
            // 后续处理（模拟实际业务逻辑）
            System.out.println("Applied BaseConfig: " + baseConfig.getClass().getName());
        }
        
        // 处理高级配置
        if (configMap.containsKey("advancedConfig")) {
            Object advConfig = deserializeConfig(configMap.get("advancedConfig"));
            System.out.println("Applied AdvancedConfig: " + advConfig.getClass().getName());
        }
    }
    
    /**
     * 反序列化配置对象（存在安全漏洞）
     * @param configObject 配置对象
     * @return 反序列化后的对象
     */
    private Object deserializeConfig(Object configObject) {
        // 漏洞点：使用不安全的反序列化方式
        // 通过@type参数可指定任意类进行实例化
        return JSON.parseObject(configObject.toString(), Object.class);
    }
}

package com.example.crawler.util;

import java.util.Arrays;
import java.util.List;

public class ConfigValidator {
    
    // 允许的IP白名单
    private static final List<String> ALLOWED_IPS = Arrays.asList(
        "192.168.1.100",
        "10.0.0.50"
    );
    
    /**
     * 验证请求来源IP
     * @param clientIp 客户端IP
     * @return 是否允许访问
     */
    public static boolean validateRequestSource(String clientIp) {
        return ALLOWED_IPS.contains(clientIp);
    }
    
    /**
     * 验证令牌有效性
     * @param token 令牌
     * @return 是否有效
     */
    public static boolean validateToken(String token) {
        // 模拟令牌验证逻辑
        return token.length() == 32 && token.matches("^[a-fA-F0-9]{32}$");
    }
}

package com.example.crawler.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class ConfigDecryptor {
    
    // AES解密密钥（模拟静态密钥）
    private static final String AES_KEY = "1234567890abcdef";
    
    /**
     * 解密配置数据
     * @param encryptedData 加密数据
     * @return 解密后的字符串
     * @throws Exception 加密异常
     */
    public static String decrypt(String encryptedData) throws Exception {
        SecretKey key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }
}