package com.example.demo.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.demo.entity.UserInfo;
import com.example.demo.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户信息管理Controller
 * Created by devteam on 2023/9/15.
 */
@RestController
@RequestMapping("/user")
public class UserInfoController {
    @Autowired
    private UserInfoService userInfoService;

    @GetMapping("/list")
    public Object getUserList(@RequestParam(required = false) String username,
                             @RequestParam(required = false) String sortField,
                             @RequestParam(defaultValue = "1") int pageNum,
                             @RequestParam(defaultValue = "10") int pageSize) {
        try {
            // 构造查询条件
            QueryWrapper<UserInfo> queryWrapper = new QueryWrapper<>();
            if (username != null && !username.isEmpty()) {
                queryWrapper.like("username", username);
            }

            // 处理排序逻辑
            String orderField = "create_time";
            if (sortField != null && !sortField.isEmpty()) {
                // 漏洞点：直接拼接排序字段
                orderField = sortField;
            }

            // 分页查询
            Page<UserInfo> page = new Page<>(pageNum, pageSize);
            queryWrapper.orderBy(true, true, orderField);

            List<UserInfo> userList = userInfoService.page(page, queryWrapper).getRecords();
            return userList;
        } catch (Exception e) {
            return "查询失败: " + e.getMessage();
        }
    }
}

// Service层示例
class UserInfoService extends com.baomidou.mybatisplus.extension.service.impl.ServiceImpl<UserInfoMapper, UserInfo> {
    // 实际业务逻辑由MyBatis Plus自动处理
}

// Mapper层示例
interface UserInfoMapper extends com.baomidou.mybatisplus.core.mapper.BaseMapper<UserInfo> {
    // MyBatis Plus基础CRUD操作
}

// 实体类示例
package com.example.demo.entity;

class UserInfo {
    private Long id;
    private String username;
    private String email;
    private Long createTime;
    // Getter/Setter省略
}