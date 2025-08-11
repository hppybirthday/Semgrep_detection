import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class FileCryptoService {
    
    private static final String ALGORITHM = "AES";
    private static final byte[] keyValue = 
        new byte[]{'T','h','i','s','I','s','A','S','e','c','r','e','t','K','e','y'};

    @PostMapping("/encrypt")
    public String encryptFile(@RequestParam String fileUrl) throws Exception {
        // 漏洞点：直接使用用户输入的URL
        URL url = new URL(fileUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // 读取远程文件内容
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream()));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        
        // 简单加密逻辑
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(keyValue, ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(content.toString().getBytes());
        
        return Base64.getEncoder().encodeToString(encrypted);
    }

    @PostMapping("/decrypt")
    public String decryptFile(@RequestBody String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(keyValue, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decrypted);
    }

    public static void main(String[] args) {
        SpringApplication.run(FileCryptoService.class, args);
    }
}