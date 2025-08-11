package com.example.bank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import javax.persistence.*;
import java.util.Optional;

@SpringBootApplication
public class BankApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankApplication.class, args);
    }
}

@Entity
class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name; // Vulnerable input field
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
}

interface UserRepository extends JpaRepository<User, Long> {}

@Service
class UserService {
    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public User saveUser(String name) {
        User user = new User();
        user.setName(name);
        return repo.save(user);
    }

    public Optional<User> findUser(Long id) {
        return repo.findById(id);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final UserService service;

    public UserController(UserService service) {
        this.service = service;
    }

    @PostMapping
    public String createUser(@RequestParam String name) {
        User user = service.saveUser(name);
        // Vulnerable redirect with unvalidated input
        return "<html><body>" +
               "<p>User <b>" + user.getName() + "</b> created successfully</p>" +
               "<a href='/users/" + user.getId() + "'>View profile</a>" +
               "</body></html>";
    }

    @GetMapping("/{id}")
    public String viewUser(@PathVariable Long id) {
        return service.findUser(id).map(user -> 
            "<html><body>" +
            "<h1>User Profile</h1>" +
            "<div>Name: " + user.getName() + "</div>" + // Vulnerable output
            "</body></html>"
        ).orElse("Not found");
    }
}