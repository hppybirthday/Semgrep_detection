package com.example.xssmicroservice.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public String listUsers(Model model) {
        List<User> users = userService.findAll();
        model.addAttribute("users", users);
        return "user-list";
    }

    @GetMapping("/{id}")
    public String showUser(@PathVariable Long id, Model model) {
        User user = userService.findById(id);
        model.addAttribute("user", user);
        return "user-detail";
    }

    @PostMapping
    public String createUser(@ModelAttribute User user) {
        // 漏洞点：直接保存用户输入的原始内容
        userService.save(user);
        return "redirect:/users/" + user.getId();
    }
}

// Thymeleaf模板 user-detail.html
// <div th:text="${user.bio}"></div>  // 漏洞触发点

// 领域模型
class User {
    private Long id;
    private String username;
    private String bio; // 未验证/转义的用户输入
    
    // getters/setters
}

// 仓储接口
interface UserRepository {
    User save(User user);
    User findById(Long id);
    List<User> findAll();
}

// 服务层
class UserService {
    @Autowired
    UserRepository userRepository;

    public User save(User user) {
        // 应该在这里进行输入验证和转义
        return userRepository.save(user);
    }

    public User findById(Long id) {
        return userRepository.findById(id);
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }
}