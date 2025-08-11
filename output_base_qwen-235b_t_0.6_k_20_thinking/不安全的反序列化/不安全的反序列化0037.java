package com.example.vulnerableapp.user;

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService = new UserService();

    @PostMapping(consumes = "application/x-java-serialized-object")
    public String deserializeUser(HttpServletRequest request) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(request.getInputStream())) {
            User user = (User) ois.readObject();
            return userService.processUser(user);
        }
    }
}

class UserService {
    private final UserRepository userRepository = new UserRepository();

    public String processUser(User user) {
        if (user == null || user.getUsername() == null) {
            return "Invalid user data";
        }
        
        // Business logic vulnerability surface
        if (user.getMetadata() != null && user.getMetadata().containsKey("token")) {
            // Simulate token processing
            System.out.println("Processing token: " + user.getMetadata().get("token"));
        }
        
        return userRepository.save(user);
    }
}

class UserRepository {
    private static final Map<String, User> storage = new HashMap<>();

    public String save(User user) {
        storage.put(user.getUsername(), user);
        return "User " + user.getUsername() + " stored successfully";
    }
}

// Domain model
class User implements Serializable {
    private String username;
    private String email;
    private transient String password;
    private Map<String, String> metadata;

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public Map<String, String> getMetadata() { return metadata; }
    public void setMetadata(Map<String, String> metadata) { this.metadata = metadata; }
}