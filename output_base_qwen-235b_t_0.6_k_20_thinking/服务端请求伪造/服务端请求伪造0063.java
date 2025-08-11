import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.net.*;
import java.net.http.*;
import java.io.IOException;
import java.time.Duration;

@RestController
@RequestMapping("/api")
public class MetadataController {
    private final MetadataService metadataService = new MetadataService();

    @GetMapping("/fetch")
    public String fetchExternalData(@RequestParam String url) {
        try {
            return metadataService.fetchDataFromExternalService(url);
        } catch (Exception e) {
            return "Error fetching data: " + e.getMessage();
        }
    }
}

class MetadataService {
    public String fetchDataFromExternalService(String urlString) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .timeout(Duration.ofSeconds(10))
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(urlString))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}

// 模拟微服务启动类
@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }
}