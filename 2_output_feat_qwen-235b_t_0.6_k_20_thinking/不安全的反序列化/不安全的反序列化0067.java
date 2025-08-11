package com.example.securetool.controller;

import com.alibaba.fastjson.JSONObject;
import com.example.securetool.service.FileService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * 文件操作控制器（处理加密数据请求）
 */
@RestController
public class FileOperationController {
    private final FileService fileService = new FileService();

    @PostMapping("/process")
    public String processFileRequest(@RequestBody String encryptedData) {
        // 接收加密的JSON数据并处理
        return fileService.processEncryptedData(encryptedData);
    }
}

package com.example.securetool.service;

import com.alibaba.fastjson.JSONObject;
import com.example.securetool.util.DecryptionUtil;
import com.example.securetool.model.FileItem;

/**
 * 文件业务处理类（包含解密和反序列化逻辑）
 */
public class FileService {
    public String processEncryptedData(String encryptedData) {
        // 解密数据（模拟硬编码密钥）
        String decryptedJson = DecryptionUtil.decrypt(encryptedData, "secretKey123");
        
        // 反序列化为FileItem对象（漏洞点）
        FileItem fileItem = JSONObject.parseObject(decryptedJson, FileItem.class);
        
        // 业务逻辑处理（模拟文件操作）
        if (fileItem.isValid()) {
            return "Processed: " + fileItem.getFileName();
        }
        return "Invalid file item";
    }
}

package com.example.securetool.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * 解密工具类（模拟AES解密流程）
 */
public class DecryptionUtil {
    public static String decrypt(String encryptedData, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), "AES"));
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)));
        } catch (Exception e) {
            // 忽略异常处理（增加分析复杂度）
            return "{}";
        }
    }
}

package com.example.securetool.model;

/**
 * 文件实体类（包含基础文件信息）
 */
public class FileItem {
    private String fileName;
    private String filePath;
    private boolean valid;

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }
}