package com.bank.app.user;

import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void registerUser(User user) {
        // 漏洞点：未对用户输入的location字段进行HTML转义
        userRepository.save(user);
    }

    public List<User> getAllUsers() {
        return new ArrayList<>(userRepository.findAll());
    }
}

package com.bank.app.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
interface UserRepository extends JpaRepository<User, Long> {}

package com.bank.app.user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    // 漏洞点：直接存储用户输入的原始location数据
    private String location;
}

package com.bank.app.web;

import com.bank.app.user.User;
import com.bank.app.user.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.Principal;

@Controller
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(User user) {
        userService.registerUser(user);
        return "redirect:/users";
    }

    @GetMapping("/users")
    public String listUsers(Model model, Principal principal) {
        model.addAttribute("users", userService.getAllUsers());
        // 漏洞点：将未净化的用户输入直接传递给视图层
        return "users";
    }
}

// Thymeleaf模板文件（resources/templates/users.html）
// 漏洞点：在th:text中直接渲染未经转义的用户输入
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>用户列表</title>
</head>
<body>
    <h1>用户地理位置信息</h1>
    <ul>
        <li th:each="user : ${users}">
            <span th:text="${user.name}"></span> - 
            <!-- 漏洞触发点：将用户输入直接作为文本内容渲染 -->
            <!-- 恶意输入示例：<script>document.write('<img src="x" onerror="alert(document.cookie)" />')</script> -->
            <span th:text="${user.location}"></span>
        </li>
    </ul>
</body>
</html>
*/