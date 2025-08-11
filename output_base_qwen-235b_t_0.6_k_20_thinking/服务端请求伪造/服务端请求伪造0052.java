import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.logging.Logger;

@SpringBootApplication
public class SsrfApplication {
    private static final Logger logger = Logger.getLogger(SsrfApplication.class.getName());

    public static void main(String[] args) {
        SpringApplication.run(SsrfApplication.class, args);
        logger.info("Application started on port 8080");
    }
}

@RestController
class VulnerableController {
    @GetMapping("/")
    String renderForm() {
        return "<html><body><h2>External Image Viewer</h2>" +
               "<form method='POST'>" +
               "URL: <input type='text' name='imageUrl' size='60'/>" +
               "<button type='submit'>Fetch Image</button></form></body></html>";
    }

    @PostMapping("/")
    void handleRequest(@RequestParam String imageUrl, HttpServletResponse res) {
        try {
            RestTemplate client = new RestTemplate();
            byte[] imageData = client.getForObject(new URI(imageUrl), byte[].class);
            
            if (imageData != null) {
                res.setContentType("image/jpeg");
                res.getOutputStream().write(imageData);
            } else {
                res.sendError(404, "No image data received");
            }
        } catch (Exception e) {
            try {
                res.sendError(500, "Error processing request");
            } catch (Exception ignored) {}
        }
    }

    // Simulated internal service endpoint
    @GetMapping("/internal/data")
    String internalService() {
        return "{\\"sensitive_data\\": \\"SECRET_API_KEYS\\"}";
    }

    // Legacy debug endpoint exposing metadata
    @GetMapping("/debug/info")
    String debugInfo() {
        return "InstanceID: prod-server-01\
Region: us-east-1\
DB_Creds: admin:securePass123";
    }
}