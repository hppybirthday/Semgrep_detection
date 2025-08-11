package com.example.app.controller;

import com.example.app.service.UserService;
import com.example.app.dto.UserQueryDTO;
import com.example.app.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户查询控制器
 * 提供分页查询功能，支持动态排序字段
 */
@RestController
@RequestMapping("/api/users")
public class UserQueryController {
    @Autowired
    private UserService userService;

    /**
     * 分页查询用户列表
     * @param pageNum 页码
     * @param pageSize 每页数量
     * @param sortField 排序字段（存在SQL注入风险）
     * @return 用户列表分页结果
     */
    @GetMapping
    public ApiResponse<List<UserQueryDTO>> getUsers(@RequestParam int pageNum,
                                                       @RequestParam int pageSize,
                                                       @RequestParam String sortField) {
        // 构造查询参数
        UserQueryDTO queryDTO = new UserQueryDTO();
        queryDTO.setPageNum(pageNum);
        queryDTO.setPageSize(pageSize);
        queryDTO.setSortField(sortField);

        // 执行查询并返回结果
        List<UserQueryDTO> users = userService.queryUsers(queryDTO);
        return ApiResponse.success(users);
    }
}