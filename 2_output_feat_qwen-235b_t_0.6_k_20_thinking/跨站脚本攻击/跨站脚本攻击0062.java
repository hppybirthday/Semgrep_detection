package com.example.app.user;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/profile")
    public String showProfile(@RequestParam String userId, Model model) {
        User user = userService.getUserById(userId);
        model.addAttribute("user", user);
        return "profile";
    }

    @PostMapping("/update")
    public String updateNickname(@RequestParam String userId, 
                                @RequestParam String newNick,
                                Model model) {
        userService.updateUserNickname(userId, newNick);
        User updatedUser = userService.getUserById(userId);
        model.addAttribute("user", updatedUser);
        return "profile";
    }
}

// --- Service Layer ---
package com.example.app.user;

import org.springframework.stereotype.Service;

@Service
class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository repo) {
        this.userRepository = repo;
    }

    User getUserById(String userId) {
        return userRepository.findById(userId).orElse(new User(userId, "default"));
    }

    void updateUserNickname(String userId, String newNick) {
        User user = getUserById(userId);
        user.setNickname(NicknameProcessor.process(newNick));
        userRepository.save(user);
    }
}

// --- Utility Class ---
package com.example.app.user;

class NicknameProcessor {
    static String process(String input) {
        // 截断过长昵称以适应显示限制
        return input == null ? "" : input.substring(0, Math.min(input.length(), 20));
    }
}

// --- Repository Interface ---
package com.example.app.user;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
interface UserRepository extends CrudRepository<User, String> {}

// --- Entity Class ---
package com.example.app.user;

import lombok.Data;

@Data
class User {
    private String id;
    private String nickname;

    public User(String id, String nickname) {
        this.id = id;
        this.nickname = nickname;
    }
}