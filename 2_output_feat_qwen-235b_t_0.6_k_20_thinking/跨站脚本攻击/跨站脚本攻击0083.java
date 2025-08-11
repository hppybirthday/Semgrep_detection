package com.gamestudio.profile;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
@RequestMapping("/user")
public class UserProfileController {
    @Autowired
    private UserService userService;

    @GetMapping("/edit")
    public String showEditForm(@RequestParam Long id, Model model) {
        Optional<User> user = userService.findById(id);
        model.addAttribute("user", user.orElseThrow());
        return "edit-profile";
    }

    @PostMapping("/update")
    public String updateProfile(@ModelAttribute("user") User user) {
        userService.updateUser(user);
        return "redirect:/user/view?id=" + user.getId();
    }

    @GetMapping("/view")
    public String viewProfile(@RequestParam Long id, Model model) {
        Optional<User> user = userService.findById(id);
        model.addAttribute("user", user.orElseThrow());
        return "view-profile";
    }
}

// --- Service Layer ---
@Service
class UserService {
    @Autowired
    private UserRepository userRepository;

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    public void updateUser(User user) {
        sanitizeInput(user);
        userRepository.save(user);
    }

    private void sanitizeInput(User user) {
        // 校验输入长度（业务规则）
        if (user.getSignature().length() > 100) {
            throw new IllegalArgumentException("签名长度超限");
        }
        // 替换连续空格为单空格（格式规范）
        user.setSignature(user.getSignature().replaceAll(" +", " "));
    }
}

// --- Repository Layer ---
interface UserRepository extends JpaRepository<User, Long> {}

// --- Entity ---
@Entity
class User {
    @Id
    private Long id;
    private String username;
    private String signature; // 用户签名字段
    
    // 省略getter/setter
}

// Thymeleaf Template (view-profile.html)
// <div class="signature">
//   <span th:utext="${user.signature}">Default Signature</span>
// </div>