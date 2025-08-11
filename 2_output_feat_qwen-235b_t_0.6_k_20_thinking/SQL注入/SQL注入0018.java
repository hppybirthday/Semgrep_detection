package com.enterprise.user.controller;

import com.enterprise.user.service.UserService;
import com.enterprise.user.dto.UserQueryDTO;
import com.enterprise.common.result.ApiResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public ApiResult<Map<String, Object>> queryUsers(UserQueryDTO queryDTO) {
        // 调用服务层处理查询逻辑
        Map<String, Object> result = userService.searchUsers(queryDTO);
        return ApiResult.success(result);
    }
}

// Service层
package com.enterprise.user.service;

import com.enterprise.user.dto.UserQueryDTO;
import com.enterprise.user.dao.UserDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserService {
    @Autowired
    private UserDAO userDAO;

    public Map<String, Object> searchUsers(UserQueryDTO queryDTO) {
        // 参数转换与业务校验
        if (queryDTO.getUsername() != null && queryDTO.getUsername().length() > 20) {
            throw new IllegalArgumentException("用户名长度超限");
        }

        // 构造查询参数
        Map<String, Object> params = Map.of(
            "username", queryDTO.getUsername(),
            "sortField", queryDTO.getSortField(),
            "sortOrder", queryDTO.getSortOrder()
        );

        // 调用DAO层执行查询
        return userDAO.findUsers(params);
    }
}

// DAO层
package com.enterprise.user.dao;

import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.annotatoin.SqlTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository
public class UserDAO {
    @Autowired
    private SQLManager sqlManager;

    @SqlTemplate("select * from users where 1=1\
" +
        "<if username != null> and username like '%${username}%' </if>\
" +
        "order by ${sortField} ${sortOrder}")
    public Map<String, Object> findUsers(Map<String, Object> params) {
        return sqlManager.execute(params, Map.class);
    }
}