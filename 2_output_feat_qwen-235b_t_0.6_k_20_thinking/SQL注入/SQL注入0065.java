package com.example.securitydemo.controller;

import com.example.securitydemo.service.UserService;
import com.example.securitydemo.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/batchDelete")
    public Result batchDelete(@RequestBody List<Long> ids) {
        // 校验参数非空
        if (ids == null || ids.isEmpty()) {
            return Result.error("参数为空");
        }
        
        // 调用服务层删除用户
        int count = userService.deleteUsers(ids);
        return Result.success(count);
    }
}