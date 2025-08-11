package com.example.app.controller;

import com.example.app.service.UserService;
import com.example.app.model.UserQuery;
import com.example.app.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/search")
    @ApiOperation("用户分页查询")
    public Result<List<User>> searchUsers(UserQuery query) {
        // 日志记录可能暴露注入点
        System.out.println("Search query: " + query.toString());
        return Result.success(userService.searchUsers(query));
    }
}

// -----------------------------
package com.example.app.service;

import com.example.app.mapper.UserMapper;
import com.example.app.model.User;
import com.example.app.model.UserQuery;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> searchUsers(UserQuery query) {
        // 构造查询条件时未验证排序参数
        String orderColumn = "username";
        if (query.getOrderBy() != null && !query.getOrderBy().isEmpty()) {
            orderColumn = query.getOrderBy();
        }
        
        String orderDir = "ASC";
        if (query.getOrderDir() != null && !query.getOrderDir().isEmpty()) {
            orderDir = query.getOrderDir().toUpperCase();
        }
        
        return userMapper.searchUsers(
            query.getUsername(), 
            orderColumn, 
            orderDir
        );
    }
}

// -----------------------------
package com.example.app.mapper;

import com.example.app.model.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {
    // 使用${}导致SQL注入漏洞
    @Select({"<script>",
      "SELECT * FROM users WHERE 1=1",
      "<if test='username != null'>",
        "AND username LIKE CONCAT('%', #{username}, '%')",
      "</if>",
      "ORDER BY ${orderColumn} ${orderDir}",
      "</script>"})
    List<User> searchUsers(
        @Param("username") String username,
        @Param("orderColumn") String orderColumn,
        @Param("orderDir") String orderDir
    );
}

// -----------------------------
package com.example.app.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class UserQuery {
    @Schema(description = "用户名模糊匹配")
    private String username;
    
    @Schema(description = "排序字段")
    private String orderBy;
    
    @Schema(description = "排序方向 ASC/DESC")
    private String orderDir;
}

// -----------------------------
package com.example.app.common;

import lombok.Data;

@Data
public class Result<T> {
    private int code;
    private String message;
    private T data;

    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setCode(200);
        result.setMessage("success");
        result.setData(data);
        return result;
    }
}