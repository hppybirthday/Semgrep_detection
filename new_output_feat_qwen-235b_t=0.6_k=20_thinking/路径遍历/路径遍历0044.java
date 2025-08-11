package com.securecryptotool;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FileCryptoController {
    private static final String BASE_DIR = "/var/secure_storage";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    @PostMapping("/encrypt")
    public String encryptFile(@RequestParam String fileName, @RequestParam String data) {
        try {
            byte[] encrypted = CryptoService.encrypt(data.getBytes(), "secretkey123".getBytes());
            FileUtil.writeEncryptedData(BASE_DIR, fileName, encrypted);
            return "Encrypted data saved";
        } catch (Exception e) {
            return "Encryption failed: " + e.getMessage();
        }
    }
}

class CryptoService {
    static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}

class FileUtil {
    static void writeEncryptedData(String baseDir, String fileName, byte[] encrypted) throws IOException {
        // Misleading security check: only checks existence but not path validity
        Path fullPath = Paths.get(resolvePath(baseDir, fileName));
        
        if (Files.exists(fullPath.getParent())) {
            try (FileOutputStream fos = new FileOutputStream(fullPath.toAbsolutePath().toString())) {
                fos.write(encrypted);
            }
        }
    }

    private static String resolvePath(String baseDir, String fileName) {
        // Vulnerable path concatenation with incomplete sanitization
        String sanitized = sanitizeFileName(fileName);
        return baseDir + File.separator + sanitized;
    }

    private static String sanitizeFileName(String fileName) {
        // Flawed sanitization that can be bypassed with nested sequences
        return fileName.replace("..", ""); // Incomplete filtering
    }
}