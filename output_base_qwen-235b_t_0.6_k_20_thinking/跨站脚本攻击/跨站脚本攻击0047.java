package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

// 领域实体
@Entity
class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String bio;

    // 省略getter/setter
}

// 基础设施层
interface UserRepository extends JpaRepository<User, Long> {}

// 应用服务
@Service
class UserService {
    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public User createUser(String username, String bio) {
        return repo.save(new User() {{
            setUsername(username);
            setBio(bio);
        }});
    }

    public List<User> getAllUsers() {
        return repo.findAll();
    }
}

// 接口层
@Controller
@RequestMapping("/users")
class UserController {
    private final UserService service;

    public UserController(UserService service) {
        this.service = service;
    }

    @GetMapping
    public String listUsers(Model model) {
        model.addAttribute("users", service.getAllUsers());
        return "user-list";
    }

    @PostMapping
    public String createUser(@RequestParam String username, 
                           @RequestParam String bio) {
        service.createUser(username, bio);
        return "redirect:/users";
    }
}

// Thymeleaf模板：user-list.html
// <html><body>
// <h1>Users</h1>
// <div th:each="user : ${users}">
//   <h3 th:text="${user.username}"></h3> <!-- 跨站脚本漏洞点 -->
//   <p th:text="${user.bio}"></p> <!-- 跨站脚本漏洞点 -->
// </div>
// <form action="/users" method="post">
//   <input name="username" placeholder="Username">
//   <textarea name="bio" placeholder="Bio"></textarea>
//   <button type="submit">Create</button>
// </form>
// </body></html>