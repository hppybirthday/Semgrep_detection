package com.example.app.controller;

import com.alibaba.fastjson.JSON;
import com.example.app.service.FileProcessingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/secure/files")
public class FileUploadController {
    @Autowired
    private FileProcessingService fileProcessingService;

    /**
     * 处理加密文件上传
     * @param file 加密文件
     * @return 处理结果
     */
    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        try {
            // 1. 验证文件类型
            if (!isValidFileType(file.getOriginalFilename())) {
                return ResponseEntity.status(415).body("Unsupported file type");
            }

            // 2. 处理加密文件
            String result = fileProcessingService.processEncryptedFile(file);
            return ResponseEntity.ok("File processed: " + result);
            
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Internal server error");
        } catch (Exception e) {
            return ResponseEntity.status(400).body("Invalid file content");
        }
    }

    /**
     * 验证文件扩展名
     */
    private boolean isValidFileType(String filename) {
        if (filename == null) return false;
        int dotIndex = filename.lastIndexOf('.');
        if (dotIndex == -1) return false;
        
        String ext = filename.substring(dotIndex + 1).toLowerCase();
        return "xlsx".equals(ext) || "docx".equals(ext);
    }
}

// ----------------------------------

package com.example.app.service;

import com.alibaba.fastjson.JSON;
import com.example.app.model.FileMetadata;
import com.example.app.util.DecryptionUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Service
public class FileProcessingService {
    /**
     * 处理加密文件核心逻辑
     */
    public String processEncryptedFile(MultipartFile file) throws IOException {
        // 1. 读取文件内容
        byte[] fileContent = file.getBytes();
        
        // 2. 解密文件（假设使用AES-GCM加密）
        byte[] decryptedContent = DecryptionUtil.decrypt(fileContent);
        
        // 3. 解析元数据
        FileMetadata metadata = parseMetadata(decryptedContent);
        
        // 4. 验证元数据
        if (!validateMetadata(metadata)) {
            throw new IllegalArgumentException("Invalid metadata");
        }
        
        // 5. 返回处理结果
        return "Metadata: " + metadata.toString();
    }

    /**
     * 使用FastJSON解析元数据
     * 注意：此处存在不安全的反序列化漏洞
     */
    private FileMetadata parseMetadata(byte[] content) {
        // 模拟从文件内容提取JSON数据
        String jsonData = extractJsonFromContent(content);
        
        // 危险操作：直接反序列化不可信数据
        // FastJSON autoType特性允许攻击者指定任意类型
        return JSON.parseObject(jsonData, FileMetadata.class);
    }

    /**
     * 验证元数据完整性
     * 注：此验证不充分
     */
    private boolean validateMetadata(FileMetadata metadata) {
        return metadata != null && 
               metadata.getVersion() != null &&
               metadata.getVersion().startsWith("v2");
    }

    /**
     * 模拟从字节数据提取JSON字符串
     */
    private String extractJsonFromContent(byte[] content) {
        // 简化实现：假设JSON数据在字节数组开头
        return new String(content);
    }
}

// ----------------------------------

package com.example.app.model;

import java.util.Map;

/**
 * 文件元数据类
 */
public class FileMetadata {
    private String version;
    private String owner;
    private Map<String, Object> extensions;
    
    // FastJSON反序列化需要默认构造函数
    public FileMetadata() {}

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public Map<String, Object> getExtensions() {
        return extensions;
    }

    public void setExtensions(Map<String, Object> extensions) {
        this.extensions = extensions;
    }

    @Override
    public String toString() {
        return "FileMetadata{" +
                "version='" + version + '\\'' +
                ", owner='" + owner + '\\'' +
                ", extensions=" + extensions +
                '}';
    }
}

// ----------------------------------

package com.example.app.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

/**
 * 模拟解密工具类
 */
public class DecryptionUtil {
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static byte[] decrypt(byte[] cipherText) throws IOException {
        try {
            // 模拟AES-GCM解密过程
            SecretKey key = generateMockKey();
            byte[] iv = generateMockIV();
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            
            return cipher.doFinal(cipherText);
            
        } catch (Exception e) {
            throw new IOException("Decryption failed", e);
        }
    }

    private static SecretKey generateMockKey() {
        // 简化实现：返回固定密钥
        return new javax.crypto.spec.SecretKeySpec(
            "0123456789abcdef".getBytes(), "AES");
    }

    private static byte[] generateMockIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}