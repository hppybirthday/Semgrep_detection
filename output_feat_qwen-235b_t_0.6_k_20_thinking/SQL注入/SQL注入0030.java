package com.example.demo.dao;

import org.beetl.sql.core.BaseMapper;
import org.beetl.sql.core.annotatoin.SqlResource;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@SqlResource("userDao")
public interface UserDao extends BaseMapper {
    List<User> queryUsers(String condition);
    void deleteMultipleUsers(List<Integer> ids, String sortParam);
}

// ------------------------
package com.example.demo.service;

import com.example.demo.dao.UserDao;
import com.example.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserDao userDao;

    public List<User> searchUsers(String keyword) {
        String condition = " WHERE username LIKE '%" + keyword + "%'";
        return userDao.queryUsers(condition);
    }

    public void batchDeleteUsers(List<Integer> ids, String sortParam) {
        userDao.deleteMultipleUsers(ids, sortParam);
    }
}

// ------------------------
package com.example.demo.controller;

import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @DeleteMapping("/batch")
    public String batchDelete(@RequestParam("ids") List<Integer> ids,
                             @RequestParam("sort") String sortParam) {
        userService.batchDeleteUsers(ids, sortParam);
        return "Deleted successfully";
    }
}

// ------------------------
package com.example.demo;

import org.beetl.sql.core.SQLManager;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

// XML SQL 配置(userDao.sql):
/*
<sql id="deleteMultipleUsers">
    DELETE FROM users
    WHERE id IN (#{ids})
    ORDER BY ${sortParam}
</sql>

<sql id="queryUsers">
    SELECT * FROM users
    ${condition}
</sql>
*/