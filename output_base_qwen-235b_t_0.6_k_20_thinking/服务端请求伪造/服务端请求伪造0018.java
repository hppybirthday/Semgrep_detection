import java.io.*;
import java.net.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class ChatApp {
    public static void main(String[] args) {
        SpringApplication.run(ChatApp.class, args);
    }

    @PostMapping("/send")
    public String sendMessage(@RequestParam String message, 
                             @RequestParam String imageUrl) {
        try {
            // 漏洞点：直接使用用户输入的URL
            URL url = new URL(imageUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            
            // 模拟保存图片
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();
            
            // 返回消息处理结果
            return "Message sent with image: " + message + "\
Image content: " + content.toString().substring(0, Math.min(100, content.length())) + "...";
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟内部API端点
    @GetMapping("/internal/secrets")
    public String getSecrets() {
        return "TOP_SECRET_DATA_12345";
    }
}