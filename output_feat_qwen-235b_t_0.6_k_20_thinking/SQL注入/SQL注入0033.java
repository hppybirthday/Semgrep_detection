package com.example.demo.controller;

import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public Object getUsers(@RequestParam Map<String, String> params) {
        // 模拟爬虫参数接收
        String userId = params.get("userId");
        String username = params.get("username");
        String sort = params.get("sort");
        String order = params.get("order");
        
        // 危险：直接透传用户输入到服务层
        return userService.searchUsers(userId, username, sort, order);
    }
}

package com.example.demo.service;

import com.example.demo.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<Map<String, Object>> searchUsers(String userId, String username, String sort, String order) {
        // 危险：未经验证直接拼接参数
        return userMapper.searchUsers(userId, username, sort, order);
    }
}

package com.example.demo.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;
import java.util.List;
import java.util.Map;

@Mapper
public interface UserMapper {
    @Delete("DELETE FROM users WHERE id = ${userId}")
    void deleteUser(@Param("userId") String userId);

    @Select("<script>" +
            "SELECT * FROM users WHERE 1=1 " +
            "<if test='username != null'> AND name LIKE '%${username}%' </if> " +
            "<if test='userId != null'> AND id = ${userId} </if> " +
            "ORDER BY ${sort} ${order} LIMIT 100" +
            "</script>")
    List<Map<String, Object>> searchUsers(@Param("userId") String userId, 
                                           @Param("username") String username,
                                           @Param("sort") String sort, 
                                           @Param("order") String order);
}

// 模拟实体类
package com.example.demo.model;

public class User {
    private Integer id;
    private String name;
    // 省略getter/setter
}