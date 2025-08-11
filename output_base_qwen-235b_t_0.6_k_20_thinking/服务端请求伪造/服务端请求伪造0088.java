import org.springframework.boot.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.*;

@SpringBootApplication
public class MLApp {
    public static void main(String[] args) {
        SpringApplication.run(MLApp.class, args);
    }
}

@RestController
class ModelController {
    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping("/train")
    public String trainModel(@RequestParam String dataUrl) {
        try {
            String data = restTemplate.getForObject(dataUrl, String.class);
            // 模拟模型训练
            return "Model trained with data size: " + data.length();
        } catch (Exception e) {
            return "Training failed: " + e.getMessage();
        }
    }
}

// application.properties配置
// server.port=8080