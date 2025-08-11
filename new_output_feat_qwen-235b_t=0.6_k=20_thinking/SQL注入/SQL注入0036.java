package com.example.security.demo.controller;

import com.example.security.demo.service.UserService;
import com.example.security.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    @ResponseBody
    public List<User> searchUsers(@RequestParam String username, @RequestParam String email) {
        // 模拟多层调用链隐藏漏洞
        return userService.findUsers(username, email);
    }
}

package com.example.security.demo.service;

import com.example.security.demo.mapper.UserMapper;
import com.example.security.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> findUsers(String username, String email) {
        // 多步处理掩盖漏洞
        String processedName = processInput(username);
        String processedEmail = processInput(email);
        return userMapper.searchUsers(processedName, processedEmail);
    }

    private String processInput(String input) {
        // 虚假的安全检查
        if (input == null || input.isEmpty()) {
            return "";
        }
        // 未正确处理特殊字符
        return input.replace("*", "%");
    }
}

package com.example.security.demo.mapper;

import com.example.security.demo.model.User;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserMapper {
    // 存在漏洞的SQL构造
    @Select({"<script>",
        "SELECT * FROM users WHERE 1=1",
        "<if test='username != null and username != \\"\\"'>",
        "AND username LIKE '${username}'",
        "</if>",
        "<if test='email != null and email != \\"\\"'>",
        "AND email LIKE '${email}'",
        "</if>",
        "</script>"})
    List<User> searchUsers(@Param("username") String username, @Param("email") String email);
}

package com.example.security.demo.model;

public class User {
    private Long id;
    private String username;
    private String email;
    // 省略getter/setter
}