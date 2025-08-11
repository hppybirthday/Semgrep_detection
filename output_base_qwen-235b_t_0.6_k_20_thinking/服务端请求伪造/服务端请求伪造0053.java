import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/api")
class ResourceController {
    private final ResourceService resourceService;

    public ResourceController(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @GetMapping("/fetch")
    public String fetchResource(@RequestParam String url) {
        return resourceService.fetchExternalResource(url);
    }
}

class ResourceService {
    private final RestTemplate restTemplate;

    public ResourceService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchExternalResource(String targetUrl) {
        try {
            // 漏洞点：直接使用用户输入的URL发起请求
            return restTemplate.getForObject(new URI(targetUrl), String.class);
        } catch (Exception e) {
            return "Error fetching resource: " + e.getMessage();
        }
    }
}