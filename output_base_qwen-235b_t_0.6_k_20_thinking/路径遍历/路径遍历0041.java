import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class LogProcessor implements CommandLineRunner {
    private static final String BASE_PATH = "/var/data/logs/";

    @GetMapping("/logs/{fileName}")
    public String getLogData(@PathVariable String fileName) throws IOException {
        Path targetPath = Paths.get(BASE_PATH + fileName);
        if (!targetPath.normalize().startsWith(BASE_PATH)) {
            throw new SecurityException("Invalid file path");
        }
        return new String(Files.readAllBytes(targetPath));
    }

    public static void main(String[] args) {
        SpringApplication.run(LogProcessor.class, args);
    }

    @Override
    public void run(String... args) {
        System.out.println("Log Processor Service Started");
    }
}

// Vulnerable code in action:
// curl http://localhost:8080/logs/../../../../etc/passwd