package com.example.xssdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@SpringBootApplication
@Controller
public class XssVulnerableApp {
    private static final String ALGORITHM = "AES";
    private static SecretKey secretKey;

    static {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(128);
            secretKey = kg.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("AES key generation failed");
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }

    @GetMapping("/encrypt")
    public String showEncryptForm() {
        return "<html><body><h2>文件加密工具</h2>" +
               "<form method='post' action='/encrypt'>" +
               "文件名: <input type='text' name='filename'><br>" +
               "内容: <input type='text' name='content'><br>" +
               "<input type='submit' value='加密'>" +
               "</form></body></html>";
    }

    @PostMapping("/encrypt")
    public String encryptFile(@RequestParam String filename, @RequestParam String content) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(content.getBytes());
            String encrypted = Base64.getEncoder().encodeToString(encryptedBytes);
            
            // 漏洞点：直接将用户输入的filename拼接到HTML响应中
            return String.format("<html><body>" +
                "<h3>加密成功!</h3>" +
                "文件名: %s<br>" +
                "加密内容: %s<br>" +
                "<a href='/decrypt'>解密文件</a>" +
                "</body></html>", filename, encrypted);
                
        } catch (Exception e) {
            return "加密失败: " + e.getMessage();
        }
    }

    @GetMapping("/decrypt")
    public String showDecryptForm() {
        return "<html><body><h2>文件解密工具</h2>" +
               "<form method='post' action='/decrypt'>" +
               "加密内容: <input type='text' name='encryptedContent'><br>" +
               "<input type='submit' value='解密'>" +
               "</form></body></html>";
    }

    @PostMapping("/decrypt")
    public String decryptFile(@RequestParam String encryptedContent) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedContent));
            String decrypted = new String(decryptedBytes);
            
            return String.format("<html><body>" +
                "<h3>解密成功!</h3>" +
                "原始内容: %s" +
                "</body></html>", decrypted);
                
        } catch (Exception e) {
            return "解密失败: " + e.getMessage();
        }
    }
}