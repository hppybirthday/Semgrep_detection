package com.bank.example;

import java.io.*;
import java.util.Base64;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 银行用户服务控制器，包含不安全的反序列化漏洞
 */
@RestController
@RequestMapping("/bank")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService = new UserService();

    @GetMapping("/login")
    public String login(@RequestParam String username, HttpServletResponse response) {
        User user = new User(username, "customer", 0.0);
        String serializedUser = userService.serializeUser(user);
        
        Cookie cookie = new Cookie("user_profile", serializedUser);
        cookie.setPath("/bank");
        response.addCookie(cookie);
        return "Logged in as " + username;
    }

    @GetMapping("/profile")
    public String getProfile(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, "user_profile");
        if (cookie == null) return "No profile found";
        
        try {
            User user = userService.deserializeUser(cookie.getValue());
            return "Welcome " + user.getUsername() + " | Balance: $" + user.getBalance();
        } catch (Exception e) {
            logger.error("Deserialization error: ", e);
            return "Invalid profile data";
        }
    }

    @PostMapping("/transfer")
    public String transfer(@RequestParam String target, @RequestParam double amount, HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, "user_profile");
        if (cookie == null) return "Authentication required";
        
        try {
            User user = userService.deserializeUser(cookie.getValue());
            if (user.getBalance() < amount) return "Insufficient funds";
            
            // 模拟转账逻辑
            user.setBalance(user.getBalance() - amount);
            String updatedProfile = userService.serializeUser(user);
            Cookie newCookie = new Cookie("user_profile", updatedProfile);
            newCookie.setPath("/bank");
            return "Transferred $" + amount + " to " + target;
        } catch (Exception e) {
            logger.error("Deserialization error during transfer: ", e);
            return "Transfer failed";
        }
    }
}

class UserService {
    String serializeUser(User user) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(user);
            oos.flush();
            return Base64.getEncoder().encodeToString(bos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    User deserializeUser(String data) throws IOException, ClassNotFoundException {
        byte[] decoded = Base64.getDecoder().decode(data);
        ByteArrayInputStream bis = new ByteArrayInputStream(decoded);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return (User) ois.readObject();
    }
}

class User implements Serializable {
    private String username;
    private String role;
    private double balance;

    public User(String username, String role, double balance) {
        this.username = username;
        this.role = role;
        this.balance = balance;
    }

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public double getBalance() { return balance; }
    public void setBalance(double balance) { this.balance = balance; }
}