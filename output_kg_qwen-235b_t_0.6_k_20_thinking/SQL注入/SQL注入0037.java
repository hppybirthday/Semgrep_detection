package com.example.security.domain.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public User login(String username, String password) {
        // 漏洞点：直接拼接SQL语句
        return userRepository.findUser(username, password);
    }

    public List<User> searchUsers(String keyword) {
        return userRepository.searchUsers(keyword);
    }
}

interface UserRepository {
    // 漏洞实现：错误使用字符串拼接
    @Select("SELECT * FROM users WHERE username = '" + #{username} + "' AND password = '" + #{password} + "'"})
    User findUser(String username, String password);

    // 漏洞点：动态拼接like条件
    @Select("SELECT * FROM users WHERE username LIKE '%" + #{keyword} + "%'"})
    List<User> searchUsers(String keyword);
}

@RestController
@RequestMapping("/api/users")
class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public Response login(@RequestParam String username, @RequestParam String password) {
        User user = userService.login(username, password);
        return user != null ? Response.success(user) : Response.error("Login failed");
    }

    @GetMapping("/search")
    public Response search(@RequestParam String keyword) {
        return Response.success(userService.searchUsers(keyword));
    }
}

// 领域实体
class User {
    private String username;
    private String password;
    private String role;
    // getters/setters
}

// 响应包装类
class Response {
    private boolean success;
    private Object data;
    private String error;

    static Response success(Object data) {
        Response r = new Response();
        r.success = true;
        r.data = data;
        return r;
    }

    static Response error(String msg) {
        Response r = new Response();
        r.success = false;
        r.error = msg;
        return r;
    }
}