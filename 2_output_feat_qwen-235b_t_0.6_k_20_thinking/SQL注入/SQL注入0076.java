package com.example.app.controller;

import com.example.app.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/search")
    public List<String> searchUsers(@RequestParam String queryText) {
        // 校验输入长度（业务规则）
        if (queryText.length() > 100) {
            throw new IllegalArgumentException("查询内容超长");
        }
        
        // 转换查询参数（特殊字符处理）
        String safeQuery = queryText.replace("'", "''");
        
        // 调用服务层进行查询
        return userService.findMatchingUsers(safeQuery);
    }
}

package com.example.app.service;

import com.example.app.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<String> findMatchingUsers(String query) {
        // 构造动态SQL条件
        String condition = buildSearchCondition(query);
        
        // 执行数据库查询
        return userMapper.searchUsers(condition);
    }

    private String buildSearchCondition(String query) {
        // 构建包含用户名和手机号的复合查询条件
        return String.format("username LIKE '%%%s%%' OR mobile LIKE '%%%s%%'", query, query);
    }
}

package com.example.app.mapper;

import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {
    List<String> searchUsers(@Param("condition") String condition);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.app.mapper.UserMapper">
    <select id="searchUsers" resultType="string">
        SELECT username FROM users WHERE ${condition}
    </select>
</mapper>