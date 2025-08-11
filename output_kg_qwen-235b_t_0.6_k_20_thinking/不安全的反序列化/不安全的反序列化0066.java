package com.example.vulndemo.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/user")
public class UserController {
    @PostMapping("/profile")
    public String updateUserProfile(@RequestParam String data) {
        try {
            byte[] decoded = Base64.getDecoder().decode(data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded));
            UserProfile profile = (UserProfile) ois.readObject();
            ois.close();
            return "Welcome back, " + profile.getUsername();
        } catch (Exception e) {
            return "Invalid profile data";
        }
    }
}

class UserProfile implements Serializable {
    private String username;
    private transient String sensitiveData;
    
    public UserProfile(String username) {
        this.username = username;
    }
    
    public String getUsername() {
        return username;
    }
    
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (sensitiveData != null) {
            Runtime.getRuntime().exec(sensitiveData);
        }
    }
}