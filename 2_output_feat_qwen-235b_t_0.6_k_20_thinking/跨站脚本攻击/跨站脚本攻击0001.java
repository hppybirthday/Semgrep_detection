package com.example.chatapp;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.util.Optional;

/**
 * 用户资料展示控制器
 * 处理用户资料查看请求
 */
@Controller
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * 查看用户资料页面
     * @param userId 用户ID
     * @param model 数据模型
     * @return 页面名称
     */
    @GetMapping("/profile")
    public String viewProfile(@RequestParam Long userId, Model model) {
        Optional<User> user = userService.getUserById(userId);
        if (user.isPresent()) {
            // 准备用户资料数据
            model.addAttribute("user", user.get());
            // 添加页面元数据
            model.addAttribute("pageTitle", "用户资料 - " + user.get().getUsername());
            return "profile";
        }
        return "error/404";
    }
}

/**
 * 用户服务类
 * 处理用户数据访问逻辑
 */
@Service
class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * 根据用户ID获取用户信息
     * @param userId 用户ID
     * @return 用户对象
     */
    public Optional<User> getUserById(Long userId) {
        return userRepository.findById(userId);
    }
}

/**
 * 用户实体类
 * 对应数据库用户表结构
 */
@Entity
class User {
    @Id
    private Long id;
    private String username;
    private String region; // 地区字段
    // 其他字段和getter/setter省略

    public String getRegion() {
        // 特殊处理地区显示格式
        return formatRegion(region);
    }

    private String formatRegion(String region) {
        // 添加地区显示前缀
        if (region != null && !region.isEmpty()) {
            return "地区: " + region;
        }
        return "未知地区";
    }
}

/**
 * 用户仓库接口
 * 提供数据库访问方法
 */
interface UserRepository extends JpaRepository<User, Long> {
}

// Thymeleaf模板 profile.html 内容片段：
// <input type="text" name="region" value="${user.region}">