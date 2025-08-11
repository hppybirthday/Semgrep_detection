package com.bank.example;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/users")
public class UserController {
    private List<User> users = new ArrayList<>();

    @GetMapping("/register")
    public String showRegistrationForm() {
        return "<html><body><form method='post' action='/users/register'>"
               + "<input type='text' name='nickname' placeholder='Enter nickname'>"
               + "<button type='submit'>Register</button></form></body></html>";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String nickname) {
        User user = new User(nickname);
        users.add(user);
        return "redirect:/users/" + user.getId();
    }

    @GetMapping("/{id}")
    public @ResponseBody String getUserProfile(@PathVariable Long id) {
        User user = users.stream()
                         .filter(u -> u.getId().equals(id))
                         .findFirst()
                         .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        // Vulnerable: Directly injecting user input into HTML without sanitization
        return String.format("<html><body><h1>Profile</h1><div>Nickname: %s</div>"
                           + "<div>Last login: 2023-09-15</div></body></html>",
                           user.getNickname());
    }

    static class User {
        private final Long id = System.currentTimeMillis();
        private final String nickname;

        User(String nickname) {
            this.nickname = nickname;
        }

        public Long getId() {
            return id;
        }

        public String getNickname() {
            return nickname;
        }
    }
}