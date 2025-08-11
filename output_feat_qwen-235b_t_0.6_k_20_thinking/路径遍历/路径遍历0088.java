import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class MLService {
    private static final String BASE_DIR = "/opt/ml/models/";

    @GetMapping("/download")
    public String downloadModel(@RequestParam String path) {
        try {
            File file = new File(BASE_DIR + path);
            if (!file.getCanonicalPath().startsWith(BASE_DIR)) {
                return "Access Denied";
            }
            byte[] content = Files.readAllBytes(file.toPath());
            return Base64.getEncoder().encodeToString(content);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @PostMapping("/upload")
    public String uploadModel(@RequestParam String path, @RequestBody String data) {
        try {
            File file = new File(BASE_DIR + path);
            if (!file.getCanonicalPath().startsWith(BASE_DIR)) {
                return "Access Denied";
            }
            Files.write(file.toPath(), Base64.getDecoder().decode(data), StandardOpenOption.CREATE);
            return "Uploaded";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(MLService.class, args);
    }
}