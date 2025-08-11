package com.example.vulnapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/encrypt")
public class FileEncryptor {
    @PostMapping
    public String encryptFile(@RequestParam String fileContent, @RequestParam String keyUrl) {
        try {
            URL url = new URL(keyUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String key = reader.readLine();
            reader.close();
            
            // Simple XOR encryption for demonstration
            StringBuilder encrypted = new StringBuilder();
            for (int i = 0; i < fileContent.length(); i++) {
                encrypted.append((char) (fileContent.charAt(i) ^ key.charAt(i % key.length())));
            }
            return "Encrypted: " + encrypted.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @GetMapping("/decrypt")
    public String decryptFile(@RequestParam String encryptedContent, @RequestParam String keyUrl) {
        try {
            URL url = new URL(keyUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String key = reader.readLine();
            reader.close();
            
            // Simple XOR decryption
            StringBuilder decrypted = new StringBuilder();
            for (int i = 0; i < encryptedContent.length(); i++) {
                decrypted.append((char) (encryptedContent.charAt(i) ^ key.charAt(i % key.length())));
            }
            return "Decrypted: " + decrypted.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Vulnerable endpoint that allows SSRF
    @GetMapping("/fetch")
    public String fetchResource(@RequestParam String targetUrl) {
        try {
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream())
            );
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            return response.toString();
        } catch (Exception e) {
            return "Error fetching resource: " + e.getMessage();
        }
    }
}