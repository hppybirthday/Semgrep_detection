package com.example.userservice.domain;

import javax.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String role;

    // Getters and setters
}

package com.example.userservice.repository;

import com.example.userservice.domain.User;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;

@Repository
public class UserRepository {
    @PersistenceContext
    private EntityManager em;

    public User findByUsername(String username) {
        // Vulnerable SQL injection point
        String sql = "SELECT u FROM User u WHERE u.username = '" + username + "'";
        return (User) em.createQuery(sql).getSingleResult();
    }
}

package com.example.userservice.service;

import com.example.userservice.domain.User;
import com.example.userservice.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> getUserByUsername(String username) {
        return Optional.ofNullable(userRepository.findByUsername(username));
    }
}

package com.example.userservice.controller;

import com.example.userservice.service.UserService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/{username}")
    public String getUser(@PathVariable String username) {
        return userService.getUserByUsername(username)
                .map(user -> "User found: " + user.getUsername())
                .orElse("User not found");
    }
}

// Spring Boot Application
package com.example.userservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class UserServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }
}