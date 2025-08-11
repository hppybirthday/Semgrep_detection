package com.example.xss;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
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
    private String username;
    private String password;
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}

interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByUsername(String username);
}

@Controller
@RequiredArgsConstructor
class AuthController {
    private final UserRepository userRepository;

    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user, Model model) {
        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            // 漏洞点：直接拼接用户输入到错误信息
            String errorMessage = "用户名 <b>" + user.getUsername() + "</b> 注册失败：密码不能为空";
            model.addAttribute("error", errorMessage);
            return "register";
        }
        
        // 未清理用户输入直接存储
        userRepository.save(user);
        return "redirect:/login";
    }
}

// Thymeleaf模板 register.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>XSS Demo</title></head>
// <body>
//   <h2>用户注册</h2>
//   
//   <!-- 漏洞点：使用utext输出未净化的错误信息 -->
//   <div th:if="${error != null}" th:utext="${error}" style="color:red"></div>
//   
//   <form th:action="@{/register}" th:object="${user}" method="post">
//     用户名：<input type="text" th:field="*{username}"/><br/>
//     密码：<input type="password" th:field="*{password}"/><br/>
//     <input type="submit" value="注册"/>
//   </form>
// </body>
// </html>