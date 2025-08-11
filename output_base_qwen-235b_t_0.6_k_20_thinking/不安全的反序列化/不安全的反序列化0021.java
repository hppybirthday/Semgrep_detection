package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
class UserController {
    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/deserialize")
    public ResponseEntity<String> deserializeUser(@RequestBody String data) {
        try {
            User user = userService.deserializeUser(data);
            return ResponseEntity.ok("Deserialized user: " + user.getName());
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Deserialization failed");
        }
    }
}

class UserService {
    public User deserializeUser(String base64Data) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            // Vulnerable deserialization point
            Object obj = ois.readObject();
            if (obj instanceof User) {
                return (User) obj;
            }
            throw new IllegalArgumentException("Not a User object");
        }
    }
}

// Malicious class to exploit deserialization
class ExploitBean implements Serializable {
    private String command;

    public ExploitBean(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        Runtime.getRuntime().exec(command); // Arbitrary command execution
    }
}

// User class for demonstration
class User implements Serializable {
    private String name;
    private int age;

    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        return name;
    }
}