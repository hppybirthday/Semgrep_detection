package com.example.filesecurity;

import com.alibaba.fastjson.JSON;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class FileUploadController {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    // 模拟硬编码的密钥（不安全实践）
    private static final SecretKey SECRET_KEY = generateKey();

    private static SecretKey generateKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(128);
            return kg.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("生成密钥失败");
        }
    }

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile encryptedFile) throws Exception {
        // 解密过程使用不安全的ECB模式
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY);
        byte[] decryptedBytes = cipher.doFinal(encryptedFile.getBytes());
        
        // 将解密内容转换为业务对象
        Map<String, Object> configMap = FastJsonConvert.convertJSONToObject(new String(decryptedBytes), Map.class);
        
        // 模拟配置应用逻辑
        return "处理完成，配置项数: " + configMap.size();
    }

    // 模拟FastJSON工具类
    private static class FastJsonConvert {
        public static <T> T convertJSONToObject(String json, Class<T> clazz) {
            return JSON.parseObject(json, clazz);
        }
    }
}