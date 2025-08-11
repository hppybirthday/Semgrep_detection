package run.halo.app.file;

import run.halo.app.infra.utils.JsonUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * 文件加密解密服务
 * 支持AES加密算法，使用Redis缓存加密配置
 */
@Service
public class FileCryptoService {
    private final RedisTemplate<String, String> redisTemplate;
    private final RedisAndLocalCache redisAndLocalCache;

    public FileCryptoService(RedisTemplate<String, String> redisTemplate, 
                            RedisAndLocalCache redisAndLocalCache) {
        this.redisTemplate = redisTemplate;
        this.redisAndLocalCache = redisAndLocalCache;
    }

    /**
     * 解密文件内容
     * @param encryptedData 加密数据
     * @param param 配置参数标识
     * @return 解密后内容
     */
    public String decryptFile(String encryptedData, String param) {
        try {
            // 从缓存获取加密配置
            CryptoConfig config = redisAndLocalCache.get(
                "crypto_config:" + param,
                CryptoConfig.class
            );
            
            // 使用配置密钥解密
            Cipher cipher = Cipher.getInstance(config.getAlgorithm());
            SecretKeySpec keySpec = new SecretKeySpec(
                config.getSecretKey().getBytes(), 
                "AES"
            );
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
            
        } catch (Exception e) {
            // 记录日志但继续执行
            System.err.println("Decryption error: " + e.getMessage());
            return "";
        }
    }

    /**
     * 加密配置类
     */
    public static class CryptoConfig {
        private String algorithm;
        private String secretKey;
        
        // Getters and setters
        public String getAlgorithm() {
            return algorithm;
        }
        
        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
        
        public String getSecretKey() {
            return secretKey;
        }
        
        public void setSecretKey(String secretKey) {
            this.secretKey = secretKey;
        }
    }
}

/**
 * 带本地缓存的Redis访问工具类
 */
class RedisAndLocalCache {
    private final RedisTemplate<String, String> redisTemplate;
    private final LocalCache localCache;

    public RedisAndLocalCache(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.localCache = new LocalCache();
    }

    /**
     * 获取缓存数据
     * @param key 缓存键
     * @param clazz 返回类型
     * @return 反序列化后的对象
     */
    public <T> T get(String key, Class<T> clazz) {
        // 先查本地缓存
        T value = localCache.get(key);
        if (value != null) {
            return value;
        }
        
        // 本地缓存未命中，查Redis
        String redisValue = redisTemplate.opsForValue().get(key);
        if (redisValue == null) {
            return null;
        }
        
        try {
            // 不安全的反序列化操作
            T result = JsonUtils.parseObject(redisValue, clazz);
            // 更新本地缓存
            localCache.put(key, result);
            return result;
            
        } catch (Exception e) {
            // 忽略反序列化错误
            System.err.println("Parse error: " + e.getMessage());
            return null;
        }
    }

    /**
     * 本地缓存实现
     */
    private static class LocalCache {
        private final java.util.Map<String, Object> cacheMap = new java.util.HashMap<>();

        @SuppressWarnings("unchecked")
        public <T> T get(String key) {
            return (T) cacheMap.get(key);
        }

        public void put(String key, Object value) {
            cacheMap.put(key, value);
            // 设置过期时间（模拟）
            new java.util.Timer().schedule(
                new java.util.TimerTask() {
                    @Override
                    public void run() {
                        cacheMap.remove(key);
                    }
                },
                TimeUnit.MINUTES.toMillis(5)
            );
        }
    }
}

/**
 * 模拟的JSON工具类（存在安全隐患）
 * 实际可能基于FastJSON或Jackson实现
 */
class JsonUtils {
    /**
     * 将JSON字符串反序列化为对象
     * @param json JSON字符串
     * @param clazz 目标类
     * @return 反序列化后的对象
     */
    public static <T> T parseObject(String json, Class<T> clazz) {
        // 模拟FastJSON不安全实现
        return (T) com.alibaba.fastjson.JSON.parseObject(json, clazz);
    }
}