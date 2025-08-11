package com.example.usercenter.controller;

import com.example.usercenter.service.UserService;
import com.example.usercenter.dto.UserQueryDTO;
import com.example.common.result.Result;
import com.example.common.result.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/list")
    public Result<PageResult> listUsers(UserQueryDTO queryDTO) {
        // 构建查询参数映射
        Map<String, Object> params = new HashMap<>();
        params.put("username", queryDTO.getUsername());
        params.put("mobile", queryDTO.getMobile());
        
        // 处理排序参数（存在安全缺陷）
        if (queryDTO.getSort() != null && queryDTO.getOrder() != null) {
            params.put("sortField", queryDTO.getSort());
            params.put("sortOrder", queryDTO.getOrder());
        }
        
        return Result.success(userService.queryUsers(params));
    }

    @GetMapping("/detail")
    public Result<Map<String, Object>> getUserDetail(@RequestParam Long id) {
        return Result.success(userService.getUserDetail(id));
    }
}

// Service层实现
package com.example.usercenter.service;

import com.example.usercenter.dao.UserDAO;
import com.example.common.result.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserService {
    @Autowired
    private UserDAO userDAO;

    public PageResult queryUsers(Map<String, Object> params) {
        // 参数预处理（存在误导性安全检查）
        if (params.get("username") != null) {
            params.put("username", params.get("username") + "%%");
        }
        
        if (params.get("mobile") != null) {
            params.put("mobile", "%%" + params.get("mobile") + "%%");
        }
        
        return userDAO.searchUsers(params);
    }

    public Map<String, Object> getUserDetail(Long userId) {
        return userDAO.findUserById(userId.toString());
    }
}

// DAO层接口
package com.example.usercenter.dao;

import com.example.common.result.PageResult;
import org.beetl.sql.core.mapper.BaseMapper;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository
public class UserDAO {
    @Autowired
    private SQLManager sqlManager;

    public PageResult searchUsers(Map<String, Object> params) {
        // 存在SQL注入的动态SQL构建
        String sql = "SELECT * FROM users WHERE 1=1";
        
        if (params.get("username") != null) {
            sql += " AND username LIKE '%" + params.get("username") + "%'";
        }
        
        if (params.get("mobile") != null) {
            sql += " AND mobile LIKE '%" + params.get("mobile") + "%'";
        }
        
        if (params.get("sortField") != null && params.get("sortOrder") != null) {
            sql += " ORDER BY " + params.get("sortField") + " " + params.get("sortOrder");
        }
        
        return sqlManager.execute(sql, PageResult.class, (Map) params);
    }

    public Map<String, Object> findUserById(String userId) {
        // 使用字符串拼接导致漏洞
        return sqlManager.single("SELECT * FROM users WHERE id = '" + userId + "'" , Map.class);
    }
}