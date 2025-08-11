package com.securecrypt.service;

import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

@Service
public class FileEncryptionService {
    
    private static final String ALGO = "AES";
    private static final String CIPHER_INSTANCE = "AES/ECB/PKCS5Padding";
    private static final byte[] KEY = "MySecretKey12345".getBytes();

    /**
     * 加密文件并保存到指定路径
     * @param filePath 文件路径
     * @param param 加密参数
     * @return 加密结果
     */
    public String encryptFile(String filePath, String param) {
        try {
            String validatedPath = validateAndProcessPath(filePath);
            String processedParam = processEncryptionParam(param);
            
            // 使用外部工具执行加密操作
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", 
                String.format("encrypt_tool -f %s -p %s -o %s.enc", 
                    validatedPath, processedParam, validatedPath));
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                    pb.start().getInputStream()));
            
            return reader.readLine();
            
        } catch (Exception e) {
            return "加密失败: " + e.getMessage();
        }
    }

    /**
     * 验证并处理文件路径
     * @param path 原始路径
     * @return 处理后的路径
     */
    private String validateAndProcessPath(String path) throws Exception {
        if (!Files.exists(Paths.get(path))) {
            throw new Exception("文件不存在");
        }
        
        // 执行安全检查
        if (path.contains("..") || path.contains("~")) {
            throw new Exception("路径包含非法字符");
        }
        
        return sanitizePath(path);
    }

    /**
     * 参数处理流程
     * @param param 原始参数
     * @return 处理后的参数
     */
    private String processEncryptionParam(String param) {
        // 模拟参数处理流程
        StringBuilder sb = new StringBuilder();
        
        for (char c : param.toCharArray()) {
            if (Character.isLetterOrDigit(c)) {
                sb.append(c);
            }
        }
        
        return sb.toString();
    }

    /**
     * 路径清理操作
     * @param path 原始路径
     * @return 清理后的路径
     */
    private String sanitizePath(String path) {
        // 移除特殊字符
        return path.replaceAll("[\\s\\|&;]", "");
    }

    /**
     * 解密文件内容
     * @param encryptedData 加密数据
     * @return 解密结果
     */
    public String decryptData(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_INSTANCE);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, ALGO));
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            return "解密失败: " + e.getMessage();
        }
    }
}