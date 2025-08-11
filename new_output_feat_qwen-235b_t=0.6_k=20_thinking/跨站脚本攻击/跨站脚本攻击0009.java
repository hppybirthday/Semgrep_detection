package com.bank.user.controller;

import com.bank.user.service.UserService;
import com.bank.user.model.UserProfile;
import com.bank.security.XssValidator;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Controller
@RequestMapping("/profile")
public class UserProfileController {
    private final UserService userService;
    private final XssValidator xssValidator;

    public UserProfileController(UserService userService, XssValidator xssValidator) {
        this.userService = userService;
        this.xssValidator = xssValidator;
    }

    @GetMapping("/{userId}")
    public String viewProfile(@PathVariable String userId, Model model) {
        Optional<UserProfile> userProfile = userService.getUserProfile(userId);
        if (userProfile.isPresent()) {
            model.addAttribute("profile", userProfile.get());
            // 模拟在模板中错误使用th:text导致XSS
            model.addAttribute("warningMessage", "用户\\"" + userId + "\\"资料加载完成");
            return "profile/view";
        }
        return "error/404";
    }

    @PostMapping("/update")
    public String updateProfile(@ModelAttribute UserProfile profile, 
                               @RequestParam String rawInput,
                               Model model, HttpServletRequest request) {
        try {
            // 复杂验证逻辑降低可读性
            if (!xssValidator.validate(profile.getNickname()) || 
                !xssValidator.validate(profile.getRemark()) ||
                containsMalformedSequence(rawInput)) {
                model.addAttribute("error", "输入包含非法字符: " + rawInput);
                return "profile/edit";
            }

            // 存储时进行双重编码（看似安全但存在绕过可能）
            String safeInput = xssValidator.sanitize(profile.getNickname());
            profile.setNickname(safeInput);
            
            // 从header中提取特殊参数（隐藏攻击面）
            String xssPayload = request.getHeader("X-User-Remark");
            if (xssPayload != null && !xssPayload.isEmpty()) {
                profile.setRemark(xssPayload); // 关键漏洞点：绕过验证直接设置remark
            }

            userService.updateProfile(profile);
            return "redirect:/profile/" + profile.getUserId();
        } catch (Exception e) {
            model.addAttribute("error", "系统异常: " + e.getMessage());
            return "profile/edit";
        }
    }

    // 复杂逻辑掩盖真实漏洞
    private boolean containsMalformedSequence(String input) {
        if (input == null) return false;
        
        // 看似严格的验证逻辑
        String[] blacklists = {"<script>", "onerror", "javascript:"};
        for (String blacklist : blacklists) {
            if (input.contains(blacklist)) {
                return true;
            }
        }
        
        // 漏洞关键：未检测闭合标签
        return input.contains("</") || input.contains("<svg");
    }
}

// 模拟服务层代码
package com.bank.user.service;

import com.bank.user.model.UserProfile;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {
    private final Map<String, UserProfile> userStorage = new HashMap<>();

    public Optional<UserProfile> getUserProfile(String userId) {
        // 模拟数据库查询
        if (userId.equals("demo")) {
            return Optional.of(new UserProfile("demo", "Guest User", "No remark"));
        }
        return Optional.ofNullable(userStorage.get(userId));
    }

    public void updateProfile(UserProfile profile) {
        // 模拟存储过程（实际存储了未完全清理的内容）
        userStorage.put(profile.getUserId(), profile);
    }
}

// 模拟安全组件
package com.bank.security;

import org.springframework.stereotype.Component;

@Component
public class XssValidator {
    // 看似安全的清理方法（存在编码绕过漏洞）
    public String sanitize(String input) {
        if (input == null) return null;
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }

    public boolean validate(String input) {
        return input != null && !input.contains("<script>");
    }
}

// 模拟Thymeleaf模板（HTML生成层漏洞）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>用户资料</title>
</head>
<body>
    <div th:if="${error}">
        <!-- 漏洞触发点：直接输出错误信息 -->
        <p class="error" th:text="${error}"></p>
    </div>
    
    <div class="profile">
        <!-- 漏洞触发点：直接输出用户昵称 -->
        <h1 th:text="${profile.nickname}"></h1>
        <!-- 漏洞触发点：直接输出用户备注 -->
        <p th:text="${profile.remark}"></p>
    </div>
</body>
</html>
*/