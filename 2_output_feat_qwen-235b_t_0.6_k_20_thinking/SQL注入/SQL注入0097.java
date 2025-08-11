package com.example.app.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户批量删除接口
 * 提供根据条件批量删除用户功能
 */
@RestController
@RequestMapping("/api/users")
public class UserBatchDeleteController {

    @Autowired
    private UserService userService;

    /**
     * 批量删除用户接口
     * 支持根据ID列表和排序条件进行删除
     */
    @DeleteMapping("/batch")
    public ResponseResult batchDelete(
        @RequestParam List<Long> ids,
        @RequestParam(required = false) String orderField,
        @RequestParam(required = false) String sortOrder) {
        
        userService.batchDelete(ids, orderField, sortOrder);
        return ResponseResult.success();
    }
}

package com.example.app.service;

import com.example.app.dao.UserDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 用户服务类
 * 实现用户管理核心业务逻辑
 */
@Service
public class UserService {

    @Autowired
    private UserDAO userDAO;

    /**
     * 批量删除用户
     * 支持动态排序条件
     */
    public void batchDelete(List<Long> ids, String orderField, String sortOrder) {
        String idsClause = buildIdsClause(ids);
        String orderClause = buildOrderClause(orderField, sortOrder);
        String sql = String.format("DELETE FROM users WHERE id IN (%s) %s", 
            idsClause, orderClause);
        
        userDAO.executeNativeSQL(sql);
    }

    /**
     * 构建ID条件子句
     * 将Long列表转换为逗号分隔字符串
     */
    private String buildIdsClause(List<Long> ids) {
        return ids.stream()
                .map(id -> id.toString())
                .collect(Collectors.joining(","));
    }

    /**
     * 构建排序条件子句
     * 包含基础字段验证逻辑
     */
    private String buildOrderClause(String orderField, String sortOrder) {
        if (orderField == null || sortOrder == null) {
            return "";
        }
        
        if (isValidOrderField(orderField) && isValidSortOrder(sortOrder)) {
            return String.format("ORDER BY %s %s", orderField, sortOrder);
        }
        
        return "";
    }

    /**
     * 验证排序字段有效性
     * 仅允许字母数字和下划线
     */
    private boolean isValidOrderField(String field) {
        return field.matches("^[a-zA-Z0-9_]+");
    }

    /**
     * 验证排序方向有效性
     */
    private boolean isValidSortOrder(String order) {
        return order.equalsIgnoreCase("ASC") || 
               order.equalsIgnoreCase("DESC");
    }
}

package com.example.app.dao;

import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * 用户数据访问对象
 * 提供原生SQL执行能力
 */
@Repository
public class UserDAO {

    @Autowired
    private SQLManager sqlManager;

    /**
     * 执行原生SQL语句
     */
    public void executeNativeSQL(String sql) {
        sqlManager.execute(sql);
    }
}

// 响应结果封装类
class ResponseResult {
    private boolean success;
    // 省略其他字段和方法
    public static ResponseResult success() {
        return new ResponseResult();
    }
}