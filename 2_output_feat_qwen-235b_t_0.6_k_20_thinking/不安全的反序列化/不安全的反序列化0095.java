package com.example.filesecurity.service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * 文件处理服务，负责解密并解析加密文件内容
 */
public class FileProcessingService {

    /**
     * 处理加密文件内容
     * @param encryptedData 加密数据（Base64编码）
     * @param encryptionKey 加密密钥（Base64编码）
     */
    public void processEncryptedFile(String encryptedData, String encryptionKey) throws Exception {
        Object businessObject = decryptAndConvert(encryptedData, encryptionKey);
        
        if (businessObject instanceof ReportData) {
            ((ReportData) businessObject).generate();
        }
    }

    private Object decryptAndConvert(String encryptedData, String encryptionKey) throws Exception {
        if (encryptionKey.length() < 24) {
            throw new IllegalArgumentException("密钥长度不足");
        }

        byte[] decryptedBytes = decryptData(
            Base64.getDecoder().decode(encryptedData),
            Base64.getDecoder().decode(encryptionKey)
        );

        return convertToObject(decryptedBytes);
    }

    private byte[] decryptData(byte[] cipherText, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(cipherText);
    }

    private Object convertToObject(byte[] data) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }
}

// 业务数据类（模拟实际业务场景）
class ReportData implements java.io.Serializable {
    private String reportName;
    private transient java.util.Date generationTime;

    public void generate() {
        // 模拟报告生成逻辑
        generationTime = new java.util.Date();
        // 实际业务中可能涉及敏感操作
    }
}