import java.io.*;
import java.net.*;
import java.util.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class TaskManager {
    public static void main(String[] args) {
        SpringApplication.run(TaskManager.class, args);
    }
}

@RestController
@RequestMapping("/tasks")
class TaskController {
    private final TaskService taskService = new TaskService();

    @PostMapping
    public ResponseEntity<String> createTask(@RequestBody TaskRequest request) {
        try {
            taskService.processImage(request.src, request.srcB);
            return ResponseEntity.ok("Task created");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    static class TaskRequest {
        String src;
        String srcB;
    }
}

class TaskService {
    void processImage(String src, String srcB) throws IOException {
        URL[] urls = {new URL(src), new URL(srcB)};
        for (URL url : urls) {
            try (InputStream in = url.openStream()) {
                // Simulate image processing
                byte[] buffer = new byte[1024];
                while (in.read(buffer) != -1) {
                    // Process image data
                }
                System.out.println("Processed image from " + url);
            } catch (Exception e) {
                throw new IOException("Image fetch failed: " + e.getMessage());
            }
        }
    }
}

// SecurityConfig.java (simplified)
@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/tasks/**").permitAll()
            .anyRequest().authenticated();
        return http.build();
    }
}