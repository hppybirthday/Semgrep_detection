package com.example.vulnerableapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@Service
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public List<Map<String, Object>> getUsers(@RequestParam String username) {
        return userService.findUserByUsername(username);
    }
}

class UserService {
    @Autowired
    private UserRepository userRepository;

    public List<Map<String, Object>> findUserByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }
}

class UserRepository {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public List<Map<String, Object>> findUserByUsername(String username) {
        // 易受攻击的SQL拼接
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForList(sql);
    }
}

/*
云原生微服务架构中，该漏洞通过直接拼接用户输入构造SQL查询，
攻击者可通过输入恶意字符串（如：' OR '1'='1）篡改SQL逻辑，
导致敏感数据泄露或绕过安全验证机制。
*/