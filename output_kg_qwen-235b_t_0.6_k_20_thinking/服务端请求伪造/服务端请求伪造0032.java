package com.example.filesecurity;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.function.Function;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
@RequestMapping("/api/files")
public class FileSecurityService {

    // 模拟加密函数
    private static final Function<String, String> encrypt = data -> 
        Base64.getEncoder().encodeToString(data.getBytes());

    // 模拟解密函数
    private static final Function<String, String> decrypt = cipher -> 
        new String(Base64.getDecoder().decode(cipher));

    // SSRF易感的远程文件获取函数
    private String fetchRemoteFile(String fileUrl) {
        try {
            URL url = new URL(fileUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            // 模拟流式处理
            return new BufferedReader(new InputStreamReader(connection.getInputStream()))
                .lines()
                .reduce((a, b) -> a + b)
                .orElseThrow(() -> new RuntimeException("Empty file"));
        } catch (Exception e) {
            throw new RuntimeException("File fetch error: " + e.getMessage());
        }
    }

    @GetMapping("/encrypt")
    public ResponseEntity<String> encryptRemoteFile(@RequestParam String url) {
        // 危险操作：直接使用用户提供的URL
        String fileContent = fetchRemoteFile(url);
        String encrypted = encrypt.apply(fileContent);
        return ResponseEntity.ok(encrypted);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decryptFile(@RequestBody String cipher) {
        return ResponseEntity.ok(decrypt.apply(cipher));
    }

    public static void main(String[] args) {
        SpringApplication.run(FileSecurityService.class, args);
    }
}