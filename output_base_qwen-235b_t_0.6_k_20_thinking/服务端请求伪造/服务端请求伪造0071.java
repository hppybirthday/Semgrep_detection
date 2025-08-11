import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class GameServer {
    public static void main(String[] args) {
        SpringApplication.run(GameServer.class, args);
    }

    @PostMapping("/player/avatar")
    public ResponseEntity<String> setPlayerAvatar(@RequestParam String avatarUrl) {
        try {
            String content = downloadAvatar(avatarUrl);
            // Process avatar content
            return ResponseEntity.ok("Avatar downloaded: " + content.length() + " bytes");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error downloading avatar");
        }
    }

    private String downloadAvatar(String avatarUrl) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet request = new HttpGet(avatarUrl);
        
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            return EntityUtils.toString(response.getEntity());
        }
    }

    // Game status endpoint for demonstration
    @GetMapping("/status")
    public ResponseEntity<String> getServerStatus() {
        return ResponseEntity.ok("Server is running");
    }
}