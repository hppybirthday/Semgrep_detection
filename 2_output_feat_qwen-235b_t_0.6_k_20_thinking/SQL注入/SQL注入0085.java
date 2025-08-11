package com.example.project.module.user.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.project.common.utils.PageData;
import com.example.project.common.utils.Result;
import com.example.project.module.user.dto.UserDTO;
import com.example.project.module.user.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
@Api(tags = "用户管理")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/list")
    @ApiOperation("分页查询用户")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "page", value = "当前页码", paramType = "query", required = true, dataType = "int"),
        @ApiImplicitParam(name = "limit", value = "每页记录数", paramType = "query", required = true, dataType = "int"),
        @ApiImplicitParam(name = "username", value = "用户名", paramType = "query", dataType = "string"),
        @ApiImplicitParam(name = "mobile", value = "手机号", paramType = "query", dataType = "string"),
        @ApiImplicitParam(name = "sort", value = "排序字段", paramType = "query", dataType = "string"),
        @ApiImplicitParam(name = "order", value = "排序方式", paramType = "query", dataType = "string")
    })
    public Result<PageData<UserDTO>> listUsers(@RequestParam Map<String, Object> params) {
        return userService.listUsers(params);
    }
}

// Service层实现
package com.example.project.module.user.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.project.common.utils.PageData;
import com.example.project.common.utils.Result;
import com.example.project.module.user.dto.UserDTO;
import com.example.project.module.user.mapper.UserMapper;
import com.example.project.module.user.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public Result<PageData<UserDTO>> listUsers(Map<String, Object> params) {
        int page = (int) params.get("page");
        int limit = (int) params.get("limit");
        String username = (String) params.get("username");
        String mobile = (String) params.get("mobile");
        String sort = (String) params.get("sort");
        String order = (String) params.get("order");

        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        if (username != null) {
            queryWrapper.like("username", username);
        }
        if (mobile != null) {
            queryWrapper.eq("mobile", mobile);
        }

        // 构建排序条件
        String orderBy = buildOrderBy(sort, order);
        if (!orderBy.isEmpty()) {
            // 使用拼接方式构造ORDER BY子句
            queryWrapper.apply("ORDER BY " + orderBy);
        }

        Page<User> userPage = new Page<>(page, limit);
        userMapper.selectPage(userPage, queryWrapper);
        
        // 转换分页结果
        PageData<UserDTO> pageData = new PageData<>();
        pageData.setList(userPage.getRecords().stream().map(this::convertToDTO).toList());
        pageData.setTotal(userPage.getTotal());
        return Result.ok(pageData);
    }

    private String buildOrderBy(String sort, String order) {
        if (sort == null || order == null) {
            return "";
        }
        // 合并排序字段和顺序
        return sort + " " + order;
    }

    private UserDTO convertToDTO(User user) {
        UserDTO dto = new UserDTO();
        // 属性赋值逻辑
        return dto;
    }
}