package com.example.bigdata.security;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * 不安全反序列化漏洞示例
 * 在Redis数据反序列化过程中存在FastJSON类型自动转换缺陷
 */
@RestController
@RequestMapping("/api/v1/tokens")
public class TokenController {
    @Resource
    private TokenService tokenService;

    @GetMapping("/{tokenId}")
    public String getToken(@PathVariable String tokenId) {
        // 模拟从Redis获取数据并反序列化
        Token token = tokenService.validateToken(tokenId);
        return "Token Info: " + token.toString();
    }
}

@Component
class TokenService {
    @Resource
    private RedisTemplate<String, String> redisTemplate;
    
    // 伪装的安全验证方法
    public Token validateToken(String tokenId) {
        String rawData = getRawTokenData(tokenId);
        if (rawData == null || !verifySignature(rawData)) {
            throw new SecurityException("Invalid token signature");
        }
        
        // 漏洞触发点：错误地使用自动类型转换
        return JSON.parseObject(rawData, Token.class);
    }
    
    // 伪造的签名验证
    private boolean verifySignature(String data) {
        // 实际未实现有效签名验证逻辑
        return true;
    }
    
    // 模拟从Redis获取数据
    private String getRawTokenData(String tokenId) {
        return redisTemplate.opsForValue().get("token:" + tokenId);
    }
}

/**
 * RedisTokenStore模拟实际数据存储交互
 * 存在漏洞的反序列化操作
 */
@Component
class RedisTemplateTokenStore {
    @Resource
    private RedisTemplate<String, String> redisTemplate;
    
    public void storeToken(String tokenId, String tokenData) {
        // 使用JSON字符串存储数据
        redisTemplate.opsForValue().set("token:" + tokenId, tokenData, 30, TimeUnit.MINUTES);
    }
    
    public Object getTokenObject(String tokenId) {
        String data = redisTemplate.opsForValue().get("token:" + tokenId);
        if (data == null) return null;
        
        // 漏洞隐藏点：通过通用类型反序列化绕过类型检查
        return JSON.parseObject(data);
    }
}

/**
 * 漏洞利用载体类
 * 包含FastJSON反序列化gadget链
 */
class Token {
    private String id;
    private String owner;
    private long expiresAt;
    
    // FastJSON反序列化会自动调用getter/setter
    public String getTemplate() {
        // 模拟存在危险的代码执行路径
        return "";
    }
    
    // 模拟XSLT注入点
    public void setXsltData(String xsltData) {
        // 漏洞利用代码（示例）
        try {
            byte[] code = Base64.getDecoder().decode(xsltData);
            // 模拟动态类加载
            ClassLoader cl = new ClassLoader(Thread.currentThread().getContextClassLoader()) {
                Class<?> define(byte[] b) {
                    return defineClass(null, b, 0, b.length);
                }
            };
            cl.define(code).newInstance();
        } catch (Exception e) {
            // 静默处理异常
        }
    }

    @Override
    public String toString() {
        return "Token{id='" + id + "', owner='" + owner + "', expiresAt=" + expiresAt + "}";
    }
}

/**
 * Redis配置类（包含误导性安全配置）
 */
@Configuration
class RedisConfig {
    @Bean
    public RedisTemplate<String, String> redisTemplate() {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        // 错误地使用FastJSON作为序列化器
        template.setValueSerializer(new FastJsonRedisSerializer<>(Object.class));
        return template;
    }
}

/**
 * 伪装的安全序列化器（实际未进行任何安全检查）
 */
class FastJsonRedisSerializer<T> implements RedisSerializer<T> {
    private final Class<T> type;

    FastJsonRedisSerializer(Class<T> type) {
        this.type = type;
    }

    @Override
    public byte[] serialize(T t) {
        return JSON.toJSONString(t).getBytes();
    }

    @Override
    public T deserialize(byte[] bytes) {
        if (bytes == null) return null;
        // 漏洞隐藏点：错误地放宽类型限制
        return JSON.parseObject(new String(bytes), Object.class);
    }
}

// 模拟攻击载荷生成器
class ExploitGenerator {
    static String generateMaliciousToken() {
        // 实际攻击载荷（示例）
        return "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\","
            + "\\"_bytecodes\\":[\\"恶意字节码Base64编码\\"],\\"_name\\":\\"a\\",\\"_tfactory\\":{}}";
    }
}