import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

@SpringBootApplication
public class SSRFApplication {
    public static void main(String[] args) {
        SpringApplication.run(SSRFApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
class SSRFController {
    private final RestTemplate restTemplate;

    public SSRFController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/fetch")
    public String fetchResource(@RequestParam String url) {
        try {
            // 模拟任务处理层直接使用用户输入构造请求
            String response = restTemplate.getForObject(url, String.class);
            return "Response: " + response.substring(0, Math.min(200, response.length())) + "...";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟内部服务接口（攻击目标）
    @GetMapping("/internal/secret")
    public String internalSecret() {
        return "{\\"token\\":\\"INTERNAL_SECRET_123\\"}";
    }

    // 模拟FTP资源访问（协议扩展）
    @GetMapping("/ftp")
    public String ftpAccess() throws IOException {
        // 实际可能使用Apache Commons VFS等库
        return "FTP file content: " + java.nio.file.Files.readToString(
            java.nio.file.Paths.get("/etc/passwd"), java.nio.charset.StandardCharsets.UTF_8);
    }
}

// application.properties配置：
// server.port=8080
// spring.main.banner-mode=off