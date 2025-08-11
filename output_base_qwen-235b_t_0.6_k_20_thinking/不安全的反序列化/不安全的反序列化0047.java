package com.example.userservice.domain;

import java.io.Serializable;
import java.util.Objects;

public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String userId;
    private final String username;
    
    public User(String userId, String username) {
        this.userId = userId;
        this.username = username;
    }
    
    // Getters and equals/hashCode omitted for brevity
}

// Repository interface
package com.example.userservice.domain;

import java.util.Optional;

public interface UserRepository {
    Optional<User> findById(String userId);
    void save(User user);
}

// Service implementation
package com.example.userservice.application;

import com.example.userservice.domain.User;
import com.example.userservice.domain.UserRepository;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

@Service
public class UserService {
    private final UserRepository userRepository;
    
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    public void processSerializedUser(byte[] userData) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(userData))) {
            // Vulnerable deserialization without any validation
            Object obj = ois.readObject();
            if (obj instanceof User) {
                User user = (User) obj;
                userRepository.save(user);
            }
        }
    }
    
    // Simulated RMI endpoint for microservice communication
    public void handleRemoteRequest(InputStream inputStream) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(inputStream)) {
            // Vulnerable: Trusting remote input completely
            User user = (User) ois.readObject();
            userRepository.save(user);
        }
    }
}

// Controller layer
package com.example.userservice.api;

import com.example.userservice.application.UserService;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService userService;
    
    public UserController(UserService userService) {
        this.userService = userService;
    }
    
    @PostMapping("/deserialize")
    public String deserialize(@RequestBody byte[] data) throws Exception {
        userService.processSerializedUser(data);
        return "User processed";
    }
    
    // Simulated inter-service communication endpoint
    @PostMapping("/rmi")
    public String rmiProxy(InputStreamResource resource) throws Exception {
        try (InputStream is = resource.getInputStream()) {
            userService.handleRemoteRequest(is);
        }
        return "RMI processed";
    }
}