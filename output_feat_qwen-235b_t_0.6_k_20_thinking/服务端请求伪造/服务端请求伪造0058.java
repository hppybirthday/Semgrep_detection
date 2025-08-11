import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@SpringBootApplication
public class SsrfDemo {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemo.class, args);
    }
}

@RestController
class DataCleanerController {
    private final WebClient webClient = WebClient.create();

    @PostMapping("/clean")
    public Mono<String> cleanData(@RequestBody UploadFromUrlRequest request) {
        return webClient.get()
            .uri(request.getUrl())
            .retrieve()
            .bodyToMono(String.class)
            .map(this::sanitizeData)
            .map(data -> String.format("{\\"cleaned_data\\":\\"%s\\"}", data));
    }

    private String sanitizeData(String rawData) {
        return rawData.replaceAll("[\\\\s\\\
]+", " ").trim();
    }
}

class UploadFromUrlRequest {
    private String url;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}

// 漏洞触发示例：
// curl -X POST http://localhost:8080/clean 
// -H "Content-Type: application/json" 
// -d '{"url":"file:///etc/passwd"}'