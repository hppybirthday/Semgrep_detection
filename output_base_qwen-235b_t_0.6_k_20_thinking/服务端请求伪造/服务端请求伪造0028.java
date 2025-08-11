import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.*;
import java.io.*;

@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}

@RestController
class CustomerController {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/import")
    public String importCustomers(@RequestParam String url) {
        try {
            String csvData = restTemplate.getForObject(url, String.class);
            // 简化处理：实际应解析CSV并存储
            return "Imported data size: " + csvData.length();
        } catch (Exception e) {
            return "Import failed: " + e.getMessage();
        }
    }

    // 模拟内部API
    @GetMapping("/internal/secret")
    public String internalApi() {
        return "CRM_SECRET_DATA_12345";
    }
}

// application.properties:
// server.port=8080