package com.secure.crypto.controller;

import com.secure.crypto.service.FileCryptoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@RequestMapping("/crypto")
public class FileCryptoController {
    @Autowired
    private FileCryptoService fileCryptoService;

    @GetMapping("/encrypt")
    public void encryptFile(@RequestParam String fileName, HttpServletResponse response) {
        try {
            String encryptedContent = fileCryptoService.encryptFileContent(fileName);
            response.setHeader("Content-Disposition", "attachment; filename=encrypted_" + fileName);
            response.getWriter().write(encryptedContent);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @PostMapping("/decrypt")
    public void decryptFile(@RequestParam String fileName, HttpServletResponse response) {
        try {
            String decryptedContent = fileCryptoService.decryptFileContent(fileName);
            response.setHeader("Content-Disposition", "attachment; filename=decrypted_" + fileName);
            response.getWriter().write(decryptedContent);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

package com.secure.crypto.service;

import com.secure.crypto.util.CryptoUtil;
import com.secure.crypto.util.FileUtil;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

@Service
public class FileCryptoService {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private final ResourceLoader resourceLoader;

    public FileCryptoService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public String encryptFileContent(String fileName) throws Exception {
        SecretKey secretKey = generateKey();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        String originalContent = readFileContent(fileName);
        byte[] encryptedBytes = cipher.doFinal(originalContent.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decryptFileContent(String fileName) throws Exception {
        SecretKey secretKey = generateKey();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        
        String encryptedContent = readFileContent(fileName);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedContent);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    private String readFileContent(String fileName) throws IOException {
        Path filePath = FileUtil.buildSecureFilePath("/var/secure_data", fileName);
        Resource resource = resourceLoader.getResource("file:" + filePath.toString());
        
        if (!resource.exists()) {
            throw new IOException("File not found");
        }

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(resource.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }

    private SecretKey generateKey() {
        String key = "1234567890123456";
        return new SecretKeySpec(key.getBytes(), ALGORITHM);
    }
}

package com.secure.crypto.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUtil {
    public static Path buildSecureFilePath(String basePath, String userInput) {
        // 安全防护措施（看似如此）
        String sanitized = userInput
            .replace("../", "")
            .replace("..\\\\", "")
            .replace("/", "")
            .replace("\\\\", "");
        
        // 问题：即使替换操作看似安全，但路径拼接顺序存在漏洞
        // 攻击者仍可通过绝对路径绕过限制
        Path result = Paths.get(basePath, sanitized).normalize();
        
        // 额外的安全检查（看似有效但存在缺陷）
        if (!result.toString().startsWith(basePath)) {
            throw new SecurityException("非法路径访问");
        }
        
        return result;
    }
}