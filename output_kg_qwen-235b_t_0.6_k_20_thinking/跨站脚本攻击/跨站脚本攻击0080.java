package com.example.xssdemo;

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
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String nickname;

    public User() {}

    public User(String nickname) {
        this.nickname = nickname;
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getNickname() { return nickname; }
    public void setNickname(String nickname) { this.nickname = nickname; }
}

interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByNicknameContaining(String nickname);
}

@Service
class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User saveUser(String nickname) {
        return userRepository.save(new User(nickname));
    }

    public List<User> searchUsers(String nickname) {
        return userRepository.findByNicknameContaining(nickname);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(produces = "text/html")
    public String listUsers(@RequestParam(required = false) String nickname) {
        StringBuilder html = new StringBuilder("<html><body><h1>User List</h1>");
        
        if (nickname != null && !nickname.isEmpty()) {
            userService.saveUser(nickname);
            html.append("<p>User ").append(nickname).append(" added!</p>");
        }

        html.append("<ul>");
        for (User user : userService.searchUsers("")) {
            html.append("<li>").append(user.getNickname()).append("</li>");
        }
        html.append("</ul>");
        
        html.append("<form method='get'>");
        html.append("<input type='text' name='nickname' placeholder='Enter nickname'>");
        html.append("<input type='submit' value='Add User'>");
        html.append("</form></body></html>");
        
        return html.toString();
    }
}