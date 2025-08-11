import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.net.URI;

@SpringBootApplication
@RestController
@RequestMapping("/crawler")
public class VulnerableCrawler {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/fetch")
    public String fetchContent(@RequestParam String url) {
        try {
            // 不安全的URL直接拼接
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(url), String.class);
            return "Response: " + response.getBody();
        } catch (Exception e) {
            return "Error fetching content: " + e.getMessage();
        }
    }

    @GetMapping("/search")
    public String searchContent(@RequestParam String query) {
        // 模拟搜索功能，内部调用外部API
        String searchUrl = "https://api.example.com/search?q=" + query;
        ResponseEntity<String> response = restTemplate.getForEntity(searchUrl, String.class);
        return "Search results: " + response.getBody();
    }

    @GetMapping("/health")
    public String healthCheck() {
        return "Service is running";
    }

    public static void main(String[] args) {
        SpringApplication.run(VulnerableCrawler.class, args);
    }
}

// application.properties配置
// server.port=8080