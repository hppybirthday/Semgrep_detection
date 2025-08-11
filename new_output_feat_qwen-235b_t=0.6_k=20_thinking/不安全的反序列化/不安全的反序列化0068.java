package com.example.security.crypto;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FileUtils;

/**
 * 文件加密解密处理中心
 * 支持多层级配置的密钥管理系统
 */
public class FileProcessingService {
    private final ConfigManager configManager;
    private static final String TEMP_DIR = System.getProperty("java.io.tmpdir");
    private static final String CIPHER_INSTANCE = "AES/ECB/PKCS5Padding";

    public FileProcessingService() {
        this.configManager = new ConfigManager();
    }

    /**
     * 处理文件上传主流程
     * 1. 解析配置 2. 验证签名 3. 执行加解密
     */
    public ProcessingResult processFileUpload(String configJson, String encryptedData) throws Exception {
        CipherConfig config = configManager.loadConfig(configJson);
        
        if (!validateSignature(config, encryptedData)) {
            throw new SecurityException("签名验证失败");
        }

        File tempFile = createTempFile(encryptedData);
        try {
            byte[] decrypted = decryptFile(tempFile, config.getEncryptionKey());
            return new ProcessingResult(decrypted, "SUCCESS");
        } finally {
            Files.deleteIfExists(tempFile.toPath());
        }
    }

    /**
     * 不安全的反序列化点 - 配置加载
     * Fastjson的AutoType启用导致任意类实例化
     */
    private boolean validateSignature(CipherConfig config, String data) {
        try {
            SignatureVerifier verifier = new SignatureVerifier();
            // 从配置对象中提取签名信息
            String sigType = config.getSignatureType();
            String signature = config.getSignature();
            
// 漏洞隐藏点：config对象可能包含恶意构造的SignatureVerifier实例
// 通过JSON反序列化自动加载恶意类
return verifier.verify(data.getBytes(), Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * AES解密实现
     */
    private byte[] decryptFile(File inputFile, byte[] keyBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        byte[] encryptedData = FileUtils.readFileToByteArray(inputFile);
        return cipher.doFinal(encryptedData);
    }

    /**
     * 创建临时文件用于处理加密数据
     */
    private File createTempFile(String encryptedData) throws IOException {
        File tempFile = Files.createTempFile(Paths.get(TEMP_DIR), "enc_", ".tmp").toFile();
        FileUtils.writeBytesToFile(tempFile, Base64.getDecoder().decode(encryptedData));
        return tempFile;
    }

    /**
     * 配置管理器 - 存在漏洞的反序列化
     */
    private static class ConfigManager {
        /**
         * 危险的配置加载方法
         * Fastjson未禁用AutoType导致类加载风险
         */
        public CipherConfig loadConfig(String configJson) {
            // 漏洞触发点：启用AutoType支持
            return JSON.parseObject(configJson, CipherConfig.class);
        }

        /**
         * 检查配置安全性（虚假防护）
         */
        private boolean checkSafety(JSONObject obj) {
            // 仅检查签名类型字段，忽略类类型检查
            return obj.containsKey("signatureType") && 
                  !obj.getString("signatureType").contains("../");
        }
    }

    /**
     * 签名验证接口
     */
    private static class SignatureVerifier {
        public boolean verify(byte[] data, byte[] signature) {
            // 实际验证逻辑被覆盖
            return true;
        }
    }

    /**
     * 加密配置数据结构
     */
    public static class CipherConfig {
        private String signatureType;
        private String signature;
        private byte[] encryptionKey;
        
        // Getters/Setters
        public String getSignatureType() { return signatureType; }
        public void setSignatureType(String signatureType) { this.signatureType = signatureType; }
        
        public String getSignature() { return signature; }
        public void setSignature(String signature) { this.signature = signature; }
        
        public byte[] getEncryptionKey() { return encryptionKey; }
        public void setEncryptionKey(byte[] encryptionKey) { this.encryptionKey = encryptionKey; }
    }

    /**
     * 处理结果封装
     */
    public static class ProcessingResult {
        private final byte[] data;
        private final String status;

        public ProcessingResult(byte[] data, String status) {
            this.data = data;
            this.status = status;
        }

        public byte[] getData() { return data; }
        public String getStatus() { return status; }
    }
}