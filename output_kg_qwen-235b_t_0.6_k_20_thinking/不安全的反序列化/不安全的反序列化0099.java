package com.example.vulnerableapp;

import java.io.Serializable;

public class UserSession implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private String role;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}

// ----------------------

package com.example.vulnerableapp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

public class SessionService {

    public UserSession deserializeSession(String encodedSession) throws IOException, ClassNotFoundException {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedSession);
        ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return (UserSession) ois.readObject();
    }
}

// ----------------------

package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/session")
public class SessionController {

    private SessionService sessionService = new SessionService();

    @GetMapping("/login")
    public String login(@RequestParam String sessionData) {
        try {
            UserSession session = sessionService.deserializeSession(sessionData);
            return "Welcome, " + session.getUsername() + " with role " + session.getRole();
        } catch (Exception e) {
            return "Invalid session data";
        }
    }
}