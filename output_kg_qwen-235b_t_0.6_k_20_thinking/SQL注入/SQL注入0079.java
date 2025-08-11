package com.example.vulnerableapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public List<Map<String, Object>> searchUsers(@RequestParam(required = false) String username,
                                                  @RequestParam(required = false) String email) {
        return userService.findUserByCriteria(username, email);
    }
}

@Service
class UserService {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    // 易受攻击的SQL拼接方法
    public List<Map<String, Object>> findUserByCriteria(String username, String email) {
        StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE 1=1");
        
        if (username != null && !username.trim().isEmpty()) {
            sql.append(" AND username = '").append(username).append("'");
        }
        
        if (email != null && !email.trim().isEmpty()) {
            sql.append(" AND email = '").append(email).append("'");
        }

        // 使用拼接的SQL直接执行
        return jdbcTemplate.queryForList(sql.toString());
    }

    // 安全的替代方法（注释展示）
    /*
    public List<Map<String, Object>> safeFindUserByCriteria(String username, String email) {
        StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        if (username != null && !username.trim().isEmpty()) {
            sql.append(" AND username = ?");
            params.add(username);
        }
        
        if (email != null && !email.trim().isEmpty()) {
            sql.append(" AND email = ?");
            params.add(email);
        }

        return jdbcTemplate.queryForList(sql.toString(), params.toArray());
    }
    */
}

// 数据库表结构示例（实际应通过Flyway/Liquibase管理）
/*
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(100) NOT NULL
);
*/