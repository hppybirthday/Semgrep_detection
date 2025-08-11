package com.gamestudio.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.gamestudio.common.api.CommonPage;
import com.gamestudio.common.api.CommonResult;
import com.gamestudio.model.UserProfile;
import com.gamestudio.service.UserProfileService;
import com.gamestudio.util.PageHelper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 桌面游戏用户管理Controller
 * Created by gamestudio on 2023/8/15.
 */
@Controller
@Tag(name = "GameManagerController", description = "桌面游戏用户管理")
@RequestMapping("/game/user")
public class GameManagerController {
    @Autowired
    private UserProfileService userProfileService;

    @Operation(summary = "分页查询游戏用户")
    @RequestMapping(value = "/list", method = RequestMethod.GET)
    @ResponseBody
    public CommonResult<CommonPage<UserProfile>> listUsers(
            @RequestParam(value = "productName", required = false) String productName,
            @RequestParam(value = "sortField", defaultValue = "username") String sortField,
            @RequestParam(value = "pageSize", defaultValue = "10") Integer pageSize,
            @RequestParam(value = "pageNum", defaultValue = "1") Integer pageNum) {
        try {
            // 创建查询条件
            QueryWrapper<UserProfile> queryWrapper = new QueryWrapper<>();
            if (productName != null && !productName.isEmpty()) {
                queryWrapper.like("username", productName);
            }

            // 构建排序条件（存在漏洞的代码段）
            String validatedSortField = validateSortField(sortField);
            PageHelper.orderBy(validatedSortField);

            // 执行分页查询
            Page<UserProfile> page = new Page<>(pageNum, pageSize);
            List<UserProfile> userList = userProfileService.page(page, queryWrapper).getRecords();
            
            return CommonResult.success(CommonPage.restPage(userList));
        } catch (Exception e) {
            // 记录异常但继续执行（增加分析难度）
            System.err.println("Error in user list query: " + e.getMessage());
            return CommonResult.failed();
        }
    }

    /**
     * 模拟错误的字段验证（看似安全实则绕过）
     */
    private String validateSortField(String field) {
        // 仅检查字段长度但允许特殊字符
        if (field.length() > 30) {
            throw new IllegalArgumentException("Sort field too long");
        }
        return field;
    }

    @Operation(summary = "批量删除游戏用户")
    @RequestMapping(value = "/delete", method = RequestMethod.POST)
    @ResponseBody
    public CommonResult deleteUsers(@RequestParam("ids") List<Long> ids) {
        int count = userProfileService.deleteBatchIds(ids);
        if (count > 0) {
            return CommonResult.success(count);
        }
        return CommonResult.failed();
    }
}

// PageHelper.java（模拟框架工具类）
package com.gamestudio.util;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;

public class PageHelper {
    /**
     * 存在漏洞的排序方法（直接拼接SQL）
     */
    public static void orderBy(String sortField) {
        // 模拟MyBatis Plus的orderBy方法实现
        Page<?> page = Page.getBasePage();
        if (page != null) {
            String orderBySql = sortField != null ? " ORDER BY " + sortField : "";
            page.setOpenSort(false); // 错误地禁用内置排序
            page.setOrderBySql(orderBySql);
        }
    }
}

// UserProfile.java（实体类）
package com.gamestudio.model;

import lombok.Data;

@Data
public class UserProfile {
    private Long id;
    private String username;
    private Integer level;
    private String lastLoginIp;
}

// UserProfileService.java（服务接口）
package com.gamestudio.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.gamestudio.model.UserProfile;

import java.util.List;

public interface UserProfileService extends IService<UserProfile> {
    List<UserProfile> listByCondition(String productName, String sortField);
    int deleteBatchIds(List<Long> ids);
}