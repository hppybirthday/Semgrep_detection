import java.io.IOException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class ChatApplication {
    public static void main(String[] args) {
        SpringApplication.run(ChatApplication.class, args);
    }
}

@RestController
class ChatController {
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    @PostMapping("/send")
    public String handleMessage(@RequestBody MessageInput input) {
        try {
            // Vulnerable command construction
            String command = "cmd /c echo [" + input.user() + "] " + input.message();
            
            // Schedule command execution with 1s delay (simulating async chat processing)
            scheduler.schedule(() -> {
                try {
                    ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
                    Process process = pb.start();
                    process.waitFor(1, TimeUnit.SECONDS);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }, 1, TimeUnit.SECONDS);

            return "Message processed";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class MessageInput {
    private String user;
    private String message;

    public String user() { return user; }
    public String message() { return message; }
}

// Vulnerable scenario: User input is directly concatenated into system command
// Attack example: 
// user="admin" and message="test && del /Q *" will execute "cmd /c echo [admin] test && del /Q *"
// The malicious payload after && will be executed as separate command