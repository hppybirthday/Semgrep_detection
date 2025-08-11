import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import javax.imageio.ImageIO;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class GamePaymentServer {
    public static void main(String[] args) {
        SpringApplication.run(GamePaymentServer.class, args);
    }

    @RestController
    class PaymentController {
        @PostMapping("/process-payment")
        public ResponseEntity<String> handlePayment(@RequestBody PaymentRequest request) {
            try {
                BufferedImage thumbnail = getThumbnail(request.thumbnailUrl);
                // Process thumbnail for game item display
                return ResponseEntity.ok("Thumbnail processed successfully");
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Error processing thumbnail");
            }
        }

        private BufferedImage getThumbnail(String thumbnailUrl) throws Exception {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(thumbnailUrl))
                .build();
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            return ImageIO.read(new ByteArrayInputStream(response.body()));
        }
    }

    static class PaymentRequest {
        String thumbnailUrl; // Unvalidated user input
        // Additional payment fields would be here
    }
}

// Vulnerable usage example:
// curl -X POST http://game-server/process-payment 
// -H "Content-Type: application/json"
// -d '{"thumbnailUrl": "http://169.254.169.254/latest/meta-data/instance-id"}'