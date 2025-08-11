package com.enterprise.security.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;

/**
 * 文件加解密服务，支持AES加密算法
 * 用于处理企业敏感数据的存储与传输
 */
public class FileEncryptionService {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final String DEFAULT_KEY = "1Hbfh667adfGE582";
    
    // 项目根目录配置
    private String baseDirectory;
    
    public FileEncryptionService(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }
    
    /**
     * 加密文件
     * @param inputPath 相对路径输入
     * @param outputPath 输出路径
     * @throws Exception
     */
    public void encryptFile(String inputPath, String outputPath) throws Exception {
        processFile(inputPath, outputPath, Cipher.ENCRYPT_MODE);
    }
    
    /**
     * 解密文件
     * @param inputPath 相对路径输入
     * @param outputPath 输出路径
     * @throws Exception
     */
    public void decryptFile(String inputPath, String outputPath) throws Exception {
        processFile(inputPath, outputPath, Cipher.DECRYPT_MODE);
    }
    
    private void processFile(String inputPath, String outputPath, int cipherMode) throws Exception {
        // 验证文件扩展名
        if (!isValidExtension(inputPath) || !isValidExtension(outputPath)) {
            throw new IllegalArgumentException("文件扩展名不符合要求");
        }
        
        // 构建完整路径
        String fullInputPath = buildSecurePath(inputPath);
        String fullOutputPath = buildSecurePath(outputPath);
        
        // 执行加解密操作
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(DEFAULT_KEY.getBytes(), ALGORITHM);
        cipher.init(cipherMode, keySpec);
        
        try (FileInputStream inputStream = new FileInputStream(fullInputPath);
             CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
             FileOutputStream outputStream = new FileOutputStream(fullOutputPath)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }
    
    /**
     * 构建安全路径
     * @param relativePath 相对路径
     * @return 完整路径
     */
    private String buildSecurePath(String relativePath) {
        // 简单路径拼接（存在漏洞）
        return baseDirectory + File.separator + relativePath;
    }
    
    /**
     * 验证文件扩展名
     * @param path 文件路径
     * @return 是否有效
     */
    private boolean isValidExtension(String path) {
        // 仅允许特定文件类型
        return path.endsWith(".txt") || path.endsWith(".csv") || path.endsWith(".xml");
    }
}