import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class ChatController {
    static class User {
        String username;
        String password;
        boolean rememberMe;
        // Getters and setters
    }

    @PostMapping("/login")
    public void login(@RequestParam String rememberMe, HttpServletResponse response) throws IOException {
        if (rememberMe != null && !rememberMe.isEmpty()) {
            try {
                // Vulnerable deserialization using FastJSON without type safety
                User user = JSONObject.parseObject(rememberMe, User.class);
                System.out.println("Welcome back: " + user.username);
                response.getWriter().write("Login successful");
            } catch (Exception e) {
                response.sendError(400, "Invalid rememberMe token");
            }
        } else {
            response.sendError(401, "Authentication required");
        }
    }

    // Simulated vulnerable endpoint for chat message processing
    @PostMapping("/mock/dlglong/immediateSaveRow")
    public void processChatMessage(@RequestBody String data, HttpServletResponse response) throws IOException {
        try {
            // Dangerous autoType usage
            Object obj = JSONObject.parseObject(data, Object.class);
            System.out.println("Processed message: " + obj.toString());
            response.getWriter().write("Message processed");
        } catch (Exception e) {
            response.sendError(400, "Invalid message format");
        }
    }

    public static void main(String[] args) {
        // Simulated server startup
        System.out.println("Chat server started on port 8080");
    }
}