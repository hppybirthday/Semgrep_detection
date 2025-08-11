package com.example.security;

import java.io.*;
import java.nio.file.*;
import java.util.Base64;
import java.util.function.*;
import java.util.stream.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/crypto")
public class FileCryptoService {
    
    private static final String BASE_DIR = System.getProperty("user.dir") + File.separator + "secure_files";
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private static final Base64.Decoder DECODER = Base64.getDecoder();
    
    @GetMapping("/encrypt")
    public String encryptFile(@RequestParam String filePath, @RequestParam String key) throws Exception {
        File target = getFile(filePath);
        if(!target.exists()) return "File not found";
        
        byte[] data = Files.readAllBytes(target.toPath());
        byte[] encrypted = xor(data, key.getBytes());
        
        Files.write(target.toPath(), encrypted, StandardOpenOption.WRITE);
        return "Encrypted: " + ENCODER.encodeToString(encrypted);
    }
    
    @GetMapping("/decrypt")
    public String decryptFile(@RequestParam String filePath, @RequestParam String key) throws Exception {
        File target = getFile(filePath);
        if(!target.exists()) return "File not found";
        
        byte[] data = Files.readAllBytes(target.toPath());
        byte[] decrypted = xor(data, key.getBytes());
        
        Files.write(target.toPath(), decrypted, StandardOpenOption.WRITE);
        return new String(decrypted);
    }
    
    private File getFile(String relativePath) {
        // 路径遍历漏洞点：未校验路径中的../序列
        return new File(BASE_DIR + File.separator + relativePath);
    }
    
    private byte[] xor(byte[] input, byte[] key) {
        byte[] result = new byte[input.length];
        for(int i=0; i<input.length; i++) {
            result[i] = (byte)(input[i] ^ key[i % key.length]);
        }
        return result;
    }
    
    // 初始化安全目录
    static {
        try {
            Files.createDirectories(Paths.get(BASE_DIR));
        } catch (IOException e) {
            throw new RuntimeException("Failed to create base directory");
        }
    }
}