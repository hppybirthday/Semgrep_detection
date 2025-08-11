package com.example.demo.controller;

import com.example.demo.service.UserService;
import com.example.demo.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @DeleteMapping("/delete")
    public Result deleteUsers(@RequestParam("ids") List<String> ids) {
        if (ids == null || ids.isEmpty()) {
            return Result.error("ID列表不能为空");
        }
        
        // 转换为逗号分隔字符串并执行删除
        String idList = String.join(",", ids);
        int count = userService.deleteUsers(idList);
        
        return count > 0 ? Result.success() : Result.error("删除失败");
    }
}

package com.example.demo.service;

import com.example.demo.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public int deleteUsers(String ids) {
        // 模拟业务校验
        if (ids.contains("'") || ids.contains(";")) {
            throw new IllegalArgumentException("非法字符检测");
        }
        
        return userMapper.deleteUserByIds(ids);
    }
}

package com.example.demo.mapper;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {
    @Delete("DELETE FROM users WHERE id IN (${ids})")
    int deleteUserByIds(String ids);
}
