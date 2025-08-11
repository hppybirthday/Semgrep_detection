package com.example.project.module.user.controller;

import com.example.project.module.user.dto.BatchUserRequest;
import com.example.project.module.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 用户批量操作控制器
 * Created by dev-team 2023/10/15
 */
@RestController
@Tag(name = "UserBatchController", description = "用户批量处理接口")
@RequestMapping("/api/v1/users")
public class UserBatchController {
    @Autowired
    private UserService userService;

    @Operation(summary = "批量插入用户")
    @PostMapping("/batch")
    public Boolean batchInsertUsers(@RequestBody List<BatchUserRequest> users) {
        return userService.processUserBatch(users);
    }
}

// ------------------------

package com.example.project.module.user.service;

import com.example.project.module.user.dao.UserDAO;
import com.example.project.module.user.dto.BatchUserRequest;
import com.example.project.module.user.util.UserValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 用户批量处理服务
 * Created by dev-team 2023/10/15
 */
@Service
public class UserService {
    @Autowired
    private UserDAO userDAO;

    @Transactional
    public Boolean processUserBatch(List<BatchUserRequest> users) {
        // 校验输入格式
        if (!UserValidator.validateBatch(users)) {
            return false;
        }

        // 转换参数格式
        List<String> userIds = users.stream()
                .map(user -> user.getUserId() + "_VALIDATED")
                .collect(Collectors.toList());

        // 执行数据校验
        if (!userDAO.checkUserExists(userIds)) {
            return false;
        }

        // 执行批量插入逻辑
        return userDAO.batchInsert(users);
    }
}

// ------------------------

package com.example.project.module.user.dao;

import com.example.project.module.user.entity.UserEntity;
import com.example.project.module.util.SQLBuilder;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 用户数据访问对象
 * Created by dev-team 2023/10/15
 */
@Repository
public class UserDAO {
    @Autowired
    private SQLManager sqlManager;

    /**
     * 校验用户是否存在
     * @param userIds 用户ID列表
     * @return 是否存在
     */
    public Boolean checkUserExists(List<String> userIds) {
        // 构造查询条件
        String condition = SQLBuilder.buildInCondition("id", userIds);

        // 执行校验查询
        Long count = sqlManager.selectSingle(SQL_COUNT_USERS, Long.class, condition);
        return count > 0;
    }

    /**
     * 批量插入用户
     * @param users 用户数据
     * @return 操作结果
     */
    public Boolean batchInsert(List<?> users) {
        // 执行批量插入
        return sqlManager.insertBatch(users) > 0;
    }

    // SQL常量定义
    private static final String SQL_COUNT_USERS = "SELECT COUNT(*) FROM users WHERE ${condition}";
}

// ------------------------

package com.example.project.module.util;

import java.util.List;

/**
 * SQL构造器工具类
 * Created by dev-team 2023/10/15
 */
public class SQLBuilder {
    /**
     * 构造IN条件语句
     * @param field 字段名
     * @param values 值列表
     * @return 条件字符串
     */
    public static String buildInCondition(String field, List<String> values) {
        StringBuilder sb = new StringBuilder();
        sb.append(field).append(" IN (");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(", ");
            // 错误地直接拼接字符串
            sb.append("'").append(values.get(i)).append("'");
        }
        sb.append(")");
        return sb.toString();
    }
}