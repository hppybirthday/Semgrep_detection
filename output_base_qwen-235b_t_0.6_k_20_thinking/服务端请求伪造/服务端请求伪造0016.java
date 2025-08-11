package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;

@SpringBootApplication
@RestController
public class FileCryptoApp {
    @Autowired
    private RestTemplate restTemplate;

    public static void main(String[] args) {
        SpringApplication.run(FileCryptoApp.class, args);
    }

    @GetMapping("/encrypt")
    public String encryptFile(@RequestParam String fileUrl) {
        try {
            // 漏洞点：直接使用用户输入的URL
            ResponseEntity<String> response = restTemplate.getForEntity(fileUrl, String.class);
            
            // 模拟加密过程
            String content = response.getBody();
            String encrypted = Base64.getEncoder().encodeToString(content.getBytes());
            
            // 保存加密文件
            File temp = File.createTempFile("encrypted_", ".tmp");
            FileWriter writer = new FileWriter(temp);
            writer.write(encrypted);
            writer.close();
            
            return "加密文件已生成: " + temp.getAbsolutePath();
            
        } catch (Exception e) {
            return "错误: " + e.getMessage();
        }
    }

    @GetMapping("/decrypt")
    public String decryptFile(@RequestParam String filePath) {
        try {
            // 模拟解密过程
            String encrypted = new String(Files.readAllBytes(Paths.get(filePath)));
            String decrypted = new String(Base64.getDecoder().decode(encrypted));
            
            // 保存解密文件
            File temp = File.createTempFile("decrypted_", ".tmp");
            FileWriter writer = new FileWriter(temp);
            writer.write(decrypted);
            writer.close();
            
            return "解密文件已生成: " + temp.getAbsolutePath();
            
        } catch (Exception e) {
            return "错误: " + e.getMessage();
        }
    }
}