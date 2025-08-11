package com.example.app.dao;

import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.SQLReady;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UserDao {
    @Autowired
    private SQLManager sqlManager;

    public int removeByIds(String[] ids) {
        // 漏洞点：直接拼接数组参数到SQL语句中
        String idList = "'" + String.join("','", ids) + "'";
        String sql = "DELETE FROM user WHERE id IN (" + idList + ")";
        return sqlManager.executeUpdate(new SQLReady(sql));
    }
}

// Service层
package com.example.app.service;

import com.example.app.dao.UserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class UserService {
    @Autowired
    private UserDao userDao;

    public boolean deleteUser(String[] ids) {
        // 未对输入参数进行校验
        int rows = userDao.removeByIds(ids);
        return rows > 0;
    }
}

// Controller层
package com.example.app.controller;

import com.example.app.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @Autowired
    private UserService userService;

    @DeleteMapping("/delete")
    public String deleteUsers(@RequestParam("ids[]") String[] ids) {
        // 直接传递原始参数到业务层
        boolean result = userService.deleteUser(ids);
        return result ? "删除成功" : "删除失败";
    }
}

// 实体类
package com.example.app.model;

public class User {
    private String id;
    private String username;
    private String role;
    // getter/setter
}

// 配置类
package com.example.app.config;

import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.db.MySqlStyle;
import org.beetl.sql.ext.spring4.BeetlSqlDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration
public class BeetlSqlConfig {
    @Bean
    public SQLManager sqlManager(DataSource dataSource) {
        return new SQLManager(new MySqlStyle(), new BeetlSqlDataSource(dataSource));
    }
}