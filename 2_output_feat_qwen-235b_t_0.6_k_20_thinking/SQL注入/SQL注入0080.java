package com.chat.app.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.app.common.ApiResponse;
import com.chat.app.service.UserService;
import com.chat.app.model.User;
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

    @Operation(summary = "Get user list with filters")
    @GetMapping("/list")
    public ApiResponse<Page<User>> listUsers(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String mobile,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "id") String sort,
            @RequestParam(defaultValue = "asc") String order) {
        
        Page<User> page = new Page<>(pageNum, pageSize);
        return ApiResponse.success(userService.listUsers(page, username, mobile, sort, order));
    }

    @Operation(summary = "Get user details")
    @GetMapping("/detail/{id}")
    public ApiResponse<User> getUserDetail(@PathVariable String id) {
        return ApiResponse.success(userService.getUserById(id));
    }
}

// ------------------------------

package com.chat.app.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.app.mapper.UserMapper;
import com.chat.app.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public Page<User> listUsers(Page<User> page, String username, String mobile, String sort, String order) {
        // 构建查询条件
        StringBuilder condition = new StringBuilder();
        if (username != null) {
            condition.append(String.format("AND username LIKE '%%%s%%' ", username));
        }
        if (mobile != null) {
            condition.append(String.format("AND mobile LIKE '%%%s%%' ", mobile));
        }

        // 构建排序条件
        String finalCondition = condition.toString();
        return userMapper.selectUserPage(page, finalCondition, sort, order);
    }

    public User getUserById(String id) {
        return userMapper.selectById(id);
    }
}

// ------------------------------

package com.chat.app.mapper;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.chat.app.model.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.builder.annotation.ProviderContext;
import org.apache.ibatis.jdbc.SQL;

public interface UserMapper {
    @SelectProvider(type = UserSqlProvider.class, method = "selectUserPage")
    IPage<User> selectUserPage(Page<User> page, 
                              @Param("condition") String condition,
                              @Param("sort") String sort,
                              @Param("order") String order);

    @SelectProvider(type = UserSqlProvider.class, method = "selectById")
    User selectById(@Param("id") String id);
}

// ------------------------------

package com.chat.app.mapper;

import org.apache.ibatis.builder.annotation.ProviderContext;
import org.apache.ibatis.jdbc.SQL;

public class UserSqlProvider {
    public String selectUserPage(Map<String, Object> params) {
        ProviderContext context = (ProviderContext) params.get("context");
        
        return new SQL() {{
            SELECT("*");
            FROM("users");
            WHERE("1=1" + (String) params.get("condition"));
            ORDER_BY((String) params.get("sort") + " " + (String) params.get("order"));
        }}.toString();
    }

    public String selectById(Map<String, Object> params) {
        return new SQL() {{
            SELECT("*");
            FROM("users");
            WHERE("id = '" + params.get("id") + "'""); // 错误的字符串拼接
        }}.toString();
    }
}