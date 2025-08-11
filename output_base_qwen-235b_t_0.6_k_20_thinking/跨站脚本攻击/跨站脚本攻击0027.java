package com.example.bank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class BankApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public String createUser(@RequestParam String username, @RequestParam String nickname) {
        userService.saveUser(username, nickname);
        return "User created";
    }

    @GetMapping("/{id}")
    public String getUser(@PathVariable Long id) {
        User user = userService.getUser(id);
        return "<html><body><h1>User Profile</h1>" +
               "<p>Username: " + user.getUsername() + "</p>" +
               "<p>Nickname: " + user.getNickname() + "</p>" +
               "</body></html>";
    }
}

@Service
class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void saveUser(String username, String nickname) {
        User user = new User();
        user.setUsername(username);
        user.setNickname(nickname);
        userRepository.save(user);
    }

    public User getUser(Long id) {
        return userRepository.findById(id).orElseThrow();
    }
}

interface UserRepository extends JpaRepository<User, Long> {}

@Entity
class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String nickname;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getNickname() { return nickname; }
    public void setNickname(String nickname) { this.nickname = nickname; }
}