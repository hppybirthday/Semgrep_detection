package com.example.app.controller;

import com.example.app.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserBatchDeleteController {
    @Autowired
    private UserService userService;

    @DeleteMapping("/batch-delete")
    public String deleteUsers(@RequestParam String ids) {
        try {
            userService.deleteUsers(ids);
            return "删除成功";
        } catch (Exception e) {
            return "删除失败";
        }
    }
}

// Service层
package com.example.app.service;

import com.example.app.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserMapper userMapper;

    @Override
    public void deleteUsers(String ids) {
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("ID列表不能为空");
        }
        userMapper.deleteUsers(ids);
    }
}

// Mapper层
package com.example.app.mapper;

import org.apache.ibatis.annotations.Delete;

public interface UserMapper {
    @Delete("DELETE FROM users WHERE id IN (${ids})")
    void deleteUsers(String ids);
}