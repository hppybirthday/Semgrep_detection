package com.example.xss.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class XssApplication {
    public static void main(String[] args) {
        SpringApplication.run(XssApplication.class, args);
    }
}

@Entity
class User {
    @Id
    @GeneratedValue
    private Long id;
    private String username;

    // Getters and setters
}

@Entity
class ErrorLog {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String message;

    // Getters and setters
}

interface UserRepository extends JpaRepository<User, Long> {}
interface ErrorLogRepository extends JpaRepository<ErrorLog, Long> {}

@Service
class UserService {
    private final UserRepository userRepository;
    private final ErrorLogRepository errorLogRepository;

    public UserService(UserRepository repo, ErrorLogRepository logRepo) {
        this.userRepository = repo;
        this.errorLogRepository = logRepo;
    }

    public void registerUser(String username) {
        if (username == null || username.length() < 3) {
            // 漏洞点：直接存储原始输入到错误日志
            ErrorLog log = new ErrorLog();
            log.setUsername(username);
            log.setMessage("Invalid username: " + username);
            errorLogRepository.save(log);
            throw new IllegalArgumentException("Invalid username: " + username);
        }
        User user = new User();
        user.setUsername(username);
        userRepository.save(user);
    }
}

@RestController
@RequestMapping("/api")
class UserController {
    private final UserService userService;

    public UserController(UserService service) {
        this.userService = service;
    }

    @PostMapping("/register")
    public String register(@RequestParam String username) {
        try {
            userService.registerUser(username);
            return "Registration successful";
        } catch (IllegalArgumentException e) {
            return e.getMessage(); // 漏洞点：直接返回未净化的错误信息
        }
    }

    @GetMapping("/admin/logs")
    public List<ErrorLog> viewLogs(ErrorLogRepository repository) {
        return repository.findAll(); // 漏洞点：直接返回原始存储的错误日志
    }
}