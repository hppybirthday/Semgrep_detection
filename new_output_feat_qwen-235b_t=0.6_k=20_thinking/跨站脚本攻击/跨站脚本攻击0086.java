// User.java
package com.bank.core.model;

import lombok.Data;

/**
 * 用户实体类
 * @author Bank System Team
 */
@Data
public class User {
    private Long id;
    private String username;
    private String fullName;
    private String note; // 用户备注信息（存在安全隐患）
}

// UserController.java
package com.bank.core.controller;

import com.bank.core.model.User;
import com.bank.core.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户管理控制器
 * @author Bank System Team
 */
@Controller
@RequestMapping("/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * 显示用户资料页面
     */
    @GetMapping("/{id}")
    public String viewProfile(@PathVariable Long id, Model model) {
        User user = userService.getUserById(id);
        model.addAttribute("user", user);
        return "user/profile";
    }

    /**
     * 更新用户信息接口
     */
    @PostMapping("/update")
    @ResponseBody
    public String updateProfile(@RequestBody UserUpdateDTO dto) {
        try {
            userService.updateUserNote(dto.getUserId(), dto.getNote());
            return "{\\"status\\":\\"success\\"}";
        } catch (Exception e) {
            return String.format("{\\"status\\":\\"error\\",\\"message\\":\\"%s\\"}", e.getMessage());
        }
    }
}

// UserService.java
package com.bank.core.service;

import com.bank.core.model.User;
import com.bank.core.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * 用户服务类
 * @author Bank System Team
 */
@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * 获取用户信息（包含安全检查）
     */
    public User getUserById(Long id) {
        Optional<User> user = userRepository.findById(id);
        if (!user.isPresent()) {
            throw new IllegalArgumentException("User not found");
        }
        
        // 安全检查：限制备注长度（看似安全但存在绕过可能）
        User userData = user.get();
        if (userData.getNote() != null && userData.getNote().length() > 200) {
            userData.setNote(userData.getNote().substring(0, 200));
        }
        return userData;
    }

    /**
     * 更新用户备注信息
     */
    public void updateUserNote(Long userId, String note) {
        // 输入验证（仅检查长度）
        if (note == null || note.length() > 200) {
            throw new IllegalArgumentException("Note length must be <= 200");
        }
        
        // 恶意输入处理链（存在漏洞）
        String processedNote = processNoteInput(note);
        userRepository.updateNote(userId, processedNote);
    }

    /**
     * 输入处理链（看似有安全处理）
     */
    private String processNoteInput(String input) {
        // 错误的安全处理（未正确转义HTML）
        String sanitized = input.replace("<script>", "").replace("</script>", "");
        // 更复杂的过滤逻辑（存在绕过可能）
        return sanitizeSpecialChars(sanitized);
    }

    /**
     * 特殊字符处理（存在缺陷）
     */
    private String sanitizeSpecialChars(String input) {
        return input.replace("&", "&amp;")
                   .replace("\\"", "&quot;")
                   .replace("'", "&#39;");
    }
}

// UserRepository.java
package com.bank.core.repository;

import com.bank.core.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * 用户数据访问层
 * @author Bank System Team
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findById(Long id);
    
    /**
     * 更新用户备注（模拟数据库操作）
     */
    default void updateNote(Long userId, String note) {
        // 模拟数据库更新操作
        // 实际中应使用JPA更新操作
    }
}

// profile.html（Thymeleaf模板）
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>User Profile</title>
</head>
<body>
    <div class="profile-container">
        <h1 th:text="${user.fullName}">Full Name</h1>
        <div class="note-section">
            <!-- 存在XSS漏洞的渲染方式 -->
            <p th:inline="text">User Note: [[${user.note}]]</p>
            <!-- 正确方式应使用th:text而非内联文本 -->
        </div>
    </div>
</body>
</html>