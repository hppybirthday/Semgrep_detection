package com.example.filesecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class FileSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileSecurityApplication.class, args);
    }
}

@Controller
class FileController {
    private static final String ALGORITHM = "AES";
    private static final String KEY = "1234567890123456";
    private Map<String, String> fileRecords = new HashMap<>();

    @GetMapping("/encrypt")
    public String showEncryptForm() {
        return "encrypt-form";
    }

    @PostMapping("/encrypt")
    public String handleFileUpload(@RequestParam("file") MultipartFile file, 
                                  @RequestParam("filename") String filename, 
                                  Model model) {
        try {
            // Vulnerable code: Directly using user input in template without sanitization
            String originalFilename = filename.isEmpty() ? file.getOriginalFilename() : filename;
            
            // Encryption logic
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(file.getBytes());
            
            // Store record with unsafe filename
            String encoded = Base64.getEncoder().encodeToString(encrypted);
            fileRecords.put(originalFilename, encoded);
            
            // XSS Vulnerability: Unsanitized filename in model attribute
            model.addAttribute("filename", originalFilename);
            model.addAttribute("status", "Encrypted successfully!");
            
        } catch (Exception e) {
            model.addAttribute("status", "Error: " + e.getMessage());
        }
        return "encrypt-result";
    }

    @GetMapping("/decrypt/{filename}")
    public String decryptFile(@PathVariable String filename, Model model) {
        try {
            // Decryption logic
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decoded = Base64.getDecoder().decode(fileRecords.get(filename));
            byte[] decrypted = cipher.doFinal(decoded);
            
            model.addAttribute("content", new String(decrypted));
            model.addAttribute("status", "Decrypted successfully!");
            
        } catch (Exception e) {
            model.addAttribute("status", "Error: " + e.getMessage());
        }
        return "decrypt-result";
    }
}