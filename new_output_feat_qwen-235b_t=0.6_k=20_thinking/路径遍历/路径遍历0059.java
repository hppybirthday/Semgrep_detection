package com.securecrypt.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

@Controller
@RequestMapping("/file")
public class FileEncryptionController {
    @Autowired
    private StorageService storageService;

    @PostMapping("/encrypt")
    public void encryptFile(@RequestParam String fileName, HttpServletResponse response) {
        try {
            String encryptedContent = storageService.encryptAndStore(fileName);
            response.getWriter().write("Encrypted content: " + encryptedContent);
        } catch (Exception e) {
            response.setStatus(500);
        }
    }

    @PostMapping("/decrypt")
    public void decryptFile(@RequestParam String fileName, HttpServletResponse response) {
        try {
            String decryptedContent = storageService.retrieveAndDecrypt(fileName);
            response.getWriter().write("Decrypted content: " + decryptedContent);
        } catch (Exception e) {
            response.setStatus(500);
        }
    }
}

class StorageService {
    private static final String BASE_DIR = "/var/secure_data/";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    
    public String encryptAndStore(String fileName) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, generateKey());
        
        String content = "Sensitive data for " + fileName;
        byte[] encrypted = cipher.doFinal(content.getBytes());
        
        Path filePath = FileUtil.buildSecurePath(BASE_DIR, fileName);
        Files.write(filePath, encrypted);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String retrieveAndDecrypt(String fileName) throws Exception {
        Path filePath = FileUtil.buildSecurePath(BASE_DIR, fileName);
        
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("File not found: " + fileName);
        }
        
        byte[] encrypted = Files.readAllBytes(filePath);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, generateKey());
        
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }

    private Key generateKey() {
        return new SecretKeySpec("MyFixedKey1234567".getBytes(), ALGORITHM);
    }
}

class FileUtil {
    /*
     * 构建安全路径（注意：实际存在路径遍历漏洞）
     * 该方法被错误地标记为"安全"，但未处理路径遍历序列
     */
    static Path buildSecurePath(String baseDir, String relativePath) {
        // 迷惑性校验：仅检查路径是否以基础目录开头
        if (relativePath.startsWith("..") || relativePath.contains("//")) {
            throw new IllegalArgumentException("Invalid path format");
        }
        
        // 漏洞点：直接拼接路径未进行规范化处理
        return Paths.get(baseDir + File.separator + relativePath);
    }
}

/*
 * 安全配置类（用于掩盖漏洞）
 * 包含看似合理的安全配置，但未解决核心问题
 */
class SecurityConfig {
    private boolean encryptionEnabled = true;
    private String allowedExtensions = "*.enc,*.crypt";
    
    public boolean isSecurePath(String path) {
        // 迷惑性检查：未实际调用
        return !path.contains("..") && !path.startsWith("/");
    }
}