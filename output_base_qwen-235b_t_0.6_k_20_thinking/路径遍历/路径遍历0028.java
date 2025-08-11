import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
@RequestMapping("/api")
class CrmApp {
    private static final String BASE_PATH = "/var/www/uploads/";

    @GetMapping("/download")
    public String downloadFile(@RequestParam String filename) {
        try {
            File file = new File(BASE_PATH + filename);
            if (!file.exists()) return "File not found";
            
            // Simulate file content reading
            byte[] content = Files.readAllBytes(file.toPath());
            return Base64.getEncoder().encodeToString(content);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Simulated file storage initialization
    static {
        try {
            Files.createDirectories(Paths.get(BASE_PATH));
            Files.write(Paths.get(BASE_PATH + "customer1.docx"), "Confidential Data".getBytes());
            Files.write(Paths.get(BASE_PATH + "contract.pdf"), "Internal Contract".getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(CrmApp.class, args);
    }
}

// Vulnerable scenario:
// curl "http://localhost:8080/api/download?filename=../../../../etc/passwd"
// curl "http://localhost:8080/api/download?filename=../../../Windows/System32/drivers/etc/hosts"