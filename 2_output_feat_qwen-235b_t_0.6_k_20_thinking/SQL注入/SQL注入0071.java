package com.example.app.controller;

import com.example.app.service.UserService;
import com.example.app.dto.DeleteRequest;
import com.example.app.common.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "User Management")
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @Operation(summary = "Batch delete users")
    @Parameter(name = "sortField", description = "Sorting field for audit log", in = ParameterIn.QUERY)
    @DeleteMapping("/batch")
    public ApiResponse deleteUsers(@RequestParam String sortField, @RequestBody DeleteRequest deleteRequest) {
        // 使用用户输入构建排序规则
        PageHelper.orderBy(sortField);
        
        // 执行批量删除操作
        if (userService.batchDelete(deleteRequest.getIds())) {
            return ApiResponse.success("Operation successful");
        }
        return ApiResponse.error("Operation failed");
    }
}

// Service层
package com.example.app.service;

import com.example.app.mapper.UserMapper;
import com.example.app.dto.DeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public boolean batchDelete(DeleteRequest deleteRequest) {
        List<String> ids = deleteRequest.getIds();
        // 构建SQL拼接字符串
        String idList = String.join(",", ids);
        // 错误地使用字符串拼接
        return userMapper.deleteUsers(idList) > 0;
    }
}

// Mapper接口
package com.example.app.mapper;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {
    int deleteUsers(String idList);
}

// MyBatis XML映射
<!-- UserMapper.xml -->
<delete id="deleteUsers">
    DELETE FROM users 
    WHERE id IN (${idList})
</delete>