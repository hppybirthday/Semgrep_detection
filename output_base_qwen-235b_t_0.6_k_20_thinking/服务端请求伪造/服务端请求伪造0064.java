import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

@SpringBootApplication
public class FileCryptoService {
    private static final String SECRET_KEY = "1234567890123456";
    private static final String ENCRYPTION_ALGO = "AES/ECB/PKCS5Padding";

    public static void main(String[] args) {
        SpringApplication.run(FileCryptoService.class, args);
    }

    @RestController
    public static class CryptoController {
        private final RestTemplate restTemplate = new RestTemplate();

        @PostMapping("/encrypt")
        public ResponseEntity<String> encryptFile(@RequestParam String fileUrl) {
            try {
                // Vulnerable point: Directly using user input to make server-side request
                ResponseEntity<byte[]> response = restTemplate.getForEntity(fileUrl, byte[].class);
                byte[] fileData = response.getBody();
                
                // Basic file validation (insufficient)
                if (fileData == null || fileData.length == 0) {
                    return ResponseEntity.badRequest().body("Invalid file content");
                }

                // Simulate encryption
                byte[] encryptedData = encryptData(fileData);
                Path tempFile = Files.createTempFile("encrypted_", ".tmp");
                Files.write(tempFile, encryptedData);
                
                return ResponseEntity.ok("Encryption complete. File saved at: " + tempFile.toString());
                
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Error processing file: " + e.getMessage());
            }
        }

        private byte[] encryptData(byte[] data) throws Exception {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGO);
            SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return cipher.doFinal(data);
        }

        // Simulated secure endpoint (for demonstration)
        @GetMapping("/admin/internal")
        public String internalEndpoint() {
            return "Internal system data - should not be exposed";
        }
    }
}