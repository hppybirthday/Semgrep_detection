import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class FileCryptoService {
    
    public static void main(String[] args) {
        SpringApplication.run(FileCryptoService.class, args);
    }
    
    @GetMapping("/test-ds")
    public String testDataSource(
        @RequestParam String host, 
        @RequestParam int port) {
            
        try {
            // 漏洞点：直接拼接用户输入构造URL
            String targetUrl = String.format("http://%s:%d/metadata", host, port);
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            
            // 漏洞危害：返回内部服务响应内容
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            
            return "Connection successful: " + response.toString();
            
        } catch (Exception e) {
            return "Connection failed: " + e.getMessage();
        }
    }
    
    // 模拟加密接口（间接关联漏洞上下文）
    @PostMapping("/encrypt")
    public String encryptData(@RequestBody String data) {
        // 实际加密逻辑应使用安全的密钥管理
        return "Encrypted(" + data.hashCode() + ")";
    }
    
    // 模拟解密接口（间接关联漏洞上下文）
    @PostMapping("/decrypt")
    public String decryptData(@RequestBody String encryptedData) {
        // 实际解密逻辑应使用安全的密钥管理
        return "Decrypted(" + encryptedData.replace("Encrypted", "") + ")";
    }
}