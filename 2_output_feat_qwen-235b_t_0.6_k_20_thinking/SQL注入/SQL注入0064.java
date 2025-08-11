package com.example.game.controller;

import com.example.game.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户管理Controller
 */
@RestController
@Tag(name = "UserController", description = "用户管理")
@RequestMapping("/api/user")
public class UserController {
    @Autowired
    private UserService userService;

    @Operation(summary = "批量删除用户")
    @PostMapping("/delete")
    public String deleteUsers(@RequestBody List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return "参数错误";
        }
        
        // 记录删除日志（业务需求）
        StringBuilder logBuilder = new StringBuilder("删除操作：");
        for (Long id : ids) {
            logBuilder.append(id).append(",");
        }
        System.out.println(logBuilder.substring(0, logBuilder.length() - 1));
        
        try {
            userService.deleteBatch(ids);
            return "删除成功";
        } catch (Exception e) {
            return "删除失败：" + e.getMessage();
        }
    }
}

// Service层代码
package com.example.game.service;

import com.example.game.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 用户服务类
 */
@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    /**
     * 批量删除用户（含业务校验）
     */
    public void deleteBatch(List<Long> ids) {
        if (ids.size() > 100) {
            throw new IllegalArgumentException("单次删除数量不超过100");
        }
        
        // 转换为逗号分隔字符串（兼容旧系统）
        StringBuilder idStr = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            idStr.append(ids.get(i));
            if (i < ids.size() - 1) {
                idStr.append(",");
            }
        }
        
        // 调用持久层
        userMapper.delete(idStr.toString());
    }
}

// Mapper层代码
package com.example.game.mapper;

import org.apache.ibatis.annotations.Mapper;

/**
 * 用户数据访问接口
 */
@Mapper
public interface UserMapper {
    /**
     * 删除用户（按ID列表）
     */
    void delete(String ids);
}

// MyBatis XML映射
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.game.mapper.UserMapper">
  <delete id="delete">
    DELETE FROM user WHERE id IN (${ids})
  </delete>
</mapper>