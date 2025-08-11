package com.example.xss.demo.model;

import com.fasterxml.jackson.annotation.JsonRawValue;
import javax.persistence.*;

@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @JsonRawValue
    private String username;

    private String role;

    public User() {}

    public User(String username, String role) {
        this.username = username;
        this.role = role;
    }

    // Getters and setters
}

// DTO
package com.example.xss.demo.dto;

public class UserDTO {
    private String username;
    private String role;

    // Getters and setters
}

// Service
package com.example.xss.demo.service;

import com.example.xss.demo.model.User;
import com.example.xss.demo.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User createUser(String username, String role) {
        return userRepository.save(new User(username, role));
    }
}

// Repository
package com.example.xss.demo.repository;

import com.example.xss.demo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {}

// Controller
package com.example.xss.demo.controller;

import com.example.xss.demo.dto.UserDTO;
import com.example.xss.demo.service.UserService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public List<User> getAll() {
        return userService.getAllUsers();
    }

    @PostMapping
    public User create(@RequestBody UserDTO dto) {
        return userService.createUser(dto.getUsername(), dto.getRole());
    }
}

// Application.java
package com.example.xss.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}