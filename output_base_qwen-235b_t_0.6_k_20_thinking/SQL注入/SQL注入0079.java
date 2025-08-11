package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@SpringBootApplication
public class SqlInjectionDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/users")
class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        return userService.authenticate(username, password) ? "Login success" : "Invalid credentials";
    }
}

class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean authenticate(String username, String password) {
        return userRepository.findUser(username, password) != null;
    }
}

class UserRepository {
    private final JdbcTemplate jdbcTemplate;

    public UserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Map<String, Object> findUser(String username, String password) {
        // Vulnerable SQL statement
        String query = String.format("SELECT * FROM users WHERE username = '%s' AND password = '%s'",
                username.replace("'"), password.replace("'"));
        
        try {
            return jdbcTemplate.queryForMap(query);
        } catch (Exception e) {
            return null;
        }
    }
}