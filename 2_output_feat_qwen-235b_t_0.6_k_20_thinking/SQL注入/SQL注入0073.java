package com.example.project.module.user.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.project.common.PageData;
import com.example.project.common.PageUtils;
import com.example.project.module.user.model.UserInfo;
import com.example.project.module.user.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/user/list")
@Api(tags = "用户管理")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("page")
    @ApiOperation("分页查询用户")
    public PageData<UserInfo> page(@RequestParam Map<String, Object> params) {
        // 提取分页参数并设置默认值
        int pageNum = PageUtils.getPageNum(params);
        int pageSize = PageUtils.getPageSize(params);
        
        // 获取排序参数（存在漏洞）
        String orderBy = PageUtils.getOrderBy(params);
        
        Page<UserInfo> page = new Page<>(pageNum, pageSize);
        if (orderBy != null && !orderBy.isEmpty()) {
            params.put("orderBy", orderBy);
        }
        
        return userService.getUserList(page, params);
    }
}

// MyBatis Mapper XML
/*
<select id="selectUserList" resultType="UserInfo">
    SELECT * FROM users
    <where>
        status = 1
    </where>
    <if test="orderBy != null and orderBy != ''">
        ORDER BY ${orderBy}
    </if>
</select>
*/