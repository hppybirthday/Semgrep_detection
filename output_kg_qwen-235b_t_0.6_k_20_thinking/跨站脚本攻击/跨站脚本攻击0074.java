package com.example.xssdemo.user;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class UserApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserApplication.class, args);
    }
}

@Entity
class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String bio; // Vulnerable field

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getBio() { return bio; }
    public void setBio(String bio) { this.bio = bio; }
}

interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByUsernameContaining(String username);
}

@Service
class UserService {
    @Autowired
    UserRepository userRepository;

    public User saveUser(User user) {
        return userRepository.save(user);
    }

    public List<User> searchUsers(String query) {
        return userRepository.findByUsernameContaining(query);
    }
}

@Controller
class UserController {
    @Autowired
    UserService userService;

    @GetMapping("/users")
    public String listUsers(@RequestParam(name = "q", required = false) String query, Model model) {
        List<User> users = (query != null) ? userService.searchUsers(query) : (List<User>) userService.searchUsers("");
        model.addAttribute("users", users);
        return "users"; // Thymeleaf template
    }

    @PostMapping("/users")
    public String createUser(@RequestParam String username, @RequestParam String bio) {
        User user = new User();
        user.setUsername(username);
        user.setBio(bio); // Directly storing user input
        userService.saveUser(user);
        return "redirect:/users";
    }
}

// Thymeleaf template (users.html)
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//   <h1>User List</h1>
//   <form action="/users" method="post">
//     <input name="username" required/>
//     <textarea name="bio"></textarea> <!-- No input sanitization -->
//     <button type="submit">Create</button>
//   </form>
//   <div th:each="user : ${users}">
//     <h3 th:text="${user.username}"></h3>
//     <div>Biography: <span th:utext="${user.bio}"></span></div> <!-- XSS Vulnerability: Using unsafe th:utext -->
//   </div>
// </body>
// </html>