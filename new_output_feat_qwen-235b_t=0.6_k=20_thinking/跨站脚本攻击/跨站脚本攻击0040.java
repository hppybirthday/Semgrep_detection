package com.example.app.controller;

import com.example.app.service.NotificationService;
import com.example.app.service.UserService;
import com.example.app.model.User;
import com.example.app.model.Notification;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.spring6.context.webflux.SpringWebFluxContext;
import org.thymeleaf.spring6.expression.ThymeleafEvaluationContext;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.util.List;

/**
 * 用户注册控制器
 * 处理用户注册流程并生成系统通知
 */
@Controller
@RequestMapping("/register")
public class UserRegistrationController {
    
    @Resource
    private UserService userService;
    
    @Resource
    private NotificationService notificationService;

    /**
     * 显示注册表单
     */
    @GetMapping
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register-form";
    }

    /**
     * 处理注册请求
     */
    @PostMapping
    public String processRegistration(@ModelAttribute("user") User user, Model model) {
        try {
            // 存储用户并生成通知
            userService.registerUser(user);
            String rawBio = user.getBio() != null ? user.getBio() : "";
            
            // 错误：使用不安全的HTML构建方法
            String notificationContent = buildNotificationContent(rawBio);
            
            // 存储通知（包含潜在恶意内容）
            notificationService.createNotification(notificationContent);
            
            model.addAttribute("success", "注册成功");
            return "redirect:/register?success";
            
        } catch (Exception e) {
            model.addAttribute("error", "注册失败: " + e.getMessage());
            return "register-form";
        }
    }

    /**
     * 构建通知HTML内容（存在漏洞的关键点）
     */
    private String buildNotificationContent(String bioContent) {
        // 漏洞点：直接拼接HTML属性值
        // 攻击者可通过闭合引号注入脚本
        return String.format("<div class='notification' title='用户简介: %s'>新用户注册</div>", bioContent);
    }

    /**
     * 显示系统通知（触发XSS）
     */
    @GetMapping("/notifications")
    public String showNotifications(Model model) {
        List<String> notifications = notificationService.getAllNotifications();
        model.addAttribute("notifications", notifications);
        return "notifications";
    }
}

// ==================== 服务层代码 ====================
package com.example.app.service;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import com.example.app.model.User;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {
    
    // 模拟数据库
    private final List<User> userRepository = new ArrayList<>();

    public void registerUser(User user) {
        // 错误：仅对script标签进行过滤
        String sanitizedBio = sanitizeBio(user.getBio());
        user.setBio(sanitizedBio);
        userRepository.add(user);
    }

    /**
     * 不充分的输入过滤（可被绕过）
     */
    private String sanitizeBio(String bio) {
        if (!StringUtils.hasText(bio)) return bio;
        
        // 仅替换<script>标签，忽略其他潜在危险属性
        return bio.replace("<script>", "&lt;script&gt;")
                  .replace("</script>", "&lt;/script&gt;");
    }
}

@Service
public class NotificationService {
    
    // 模拟持久化存储
    private final List<String> notifications = new ArrayList<>();

    public void createNotification(String content) {
        notifications.add(content);
    }

    public List<String> getAllNotifications() {
        return List.copyOf(notifications);
    }
}

// ==================== Thymeleaf模板模拟 ====================
// 在实际模板中，notifications会被直接渲染，未进行HTML转义
// templates/notifications.html
// <div class="notifications">
//   <div th:each="notification : ${notifications}"
//        th:utext="${notification}">
//   </div>
// </div>