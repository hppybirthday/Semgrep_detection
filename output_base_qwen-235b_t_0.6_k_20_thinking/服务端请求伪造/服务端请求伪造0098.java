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

    @GetMapping("/send")
    public String sendMessage(@RequestParam String url) {
        try {
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setRequestMethod("GET");
            
            if (conn.getResponseCode() == 200) {
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }
                in.close();
                return "Message sent: " + content.toString();
            }
            return "Failed to send message";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @PostMapping("/upload")
    public String uploadImage(@RequestParam String imageUrl) {
        try {
            URL image = new URL(imageUrl);
            HttpURLConnection conn = (HttpURLConnection) image.openConnection();
            conn.setRequestMethod("GET");
            
            // 模拟保存图片
            Map<String, String> metadata = new HashMap<>();
            metadata.put("size", conn.getHeaderField("Content-Length"));
            metadata.put("type", conn.getContentType());
            
            return "Image saved: " + metadata.toString();
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}