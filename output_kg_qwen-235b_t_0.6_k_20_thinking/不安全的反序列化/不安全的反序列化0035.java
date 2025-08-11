package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@SpringBootApplication
public class VulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApp.class, args);
    }

    @RestController
    @RequestMapping("/api/users")
    public static class UserController {
        private final UserService userService = new UserService();

        @PostMapping("/update")
        public String updateUser(@RequestBody UserUpdateRequest request) {
            try {
                User user = userService.deserializeUser(request.getSerializedUser());
                return userService.updateUserProfile(user);
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    public static class UserUpdateRequest {
        private String serializedUser;

        public String getSerializedUser() {
            return serializedUser;
        }

        public void setSerializedUser(String serializedUser) {
            this.serializedUser = serializedUser;
        }
    }

    public static class UserService {
        public User deserializeUser(String base64Data) throws IOException, ClassNotFoundException {
            byte[] data = Base64.getDecoder().decode(base64Data);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                return (User) ois.readObject();
            }
        }

        public String updateUserProfile(User user) {
            // 模拟业务逻辑
            return "Profile updated for user: " + user.getUsername();
        }
    }

    public static class User implements Serializable {
        private String username;
        private transient String password; // 敏感字段

        public User(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            // 模拟危险操作
            if (username != null && username.contains("malicious")) {
                Runtime.getRuntime().exec("calc"); // 模拟RCE
            }
        }
    }
}