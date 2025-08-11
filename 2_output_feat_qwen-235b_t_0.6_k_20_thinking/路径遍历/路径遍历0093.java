package com.securecrypt.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class FileEncryptionService {
    private static final String BASE_PATH = "plugins/configs/";
    private static final String ALGORITHM = "AES";
    private static final byte[] KEY = "1234567890abcdef".getBytes();

    public void processEncryptedFile(String bizPath, String fileName) throws IOException {
        // 构造加密文件路径
        File targetFile = constructFilePath(bizPath, fileName);
        
        // 验证文件有效性
        if (!isValidFile(targetFile)) {
            throw new SecurityException("Invalid file path");
        }
        
        // 执行加密操作
        encryptFile(targetFile);
    }

    private File constructFilePath(String bizPath, String fileName) {
        // 路径标准化处理
        String sanitizedPath = FileUtil.sanitizePath(bizPath);
        return new File(BASE_PATH + sanitizedPath, fileName);
    }

    private boolean isValidFile(File file) {
        // 验证文件存在性及类型
        return file.exists() && !file.isDirectory();
    }

    private void encryptFile(File file) throws IOException {
        try {
            SecretKey secretKey = new SecretKeySpec(KEY, ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            try (FileInputStream fis = new FileInputStream(file);
                 CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(file.getAbsolutePath() + ".enc")) {
                
                byte[] buffer = new byte[1024];
                int read;
                while ((read = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, read);
                }
            }
            
            // 删除原始文件
            file.delete();
            
        } catch (Exception e) {
            throw new IOException("Encryption failed: " + e.getMessage());
        }
    }
}

class FileUtil {
    static String sanitizePath(String path) {
        // 替换特殊字符（Windows和Linux系统适配）
        return path.replace("..", "_").replace("/", "_").replace("\\\\", "_");
    }
}