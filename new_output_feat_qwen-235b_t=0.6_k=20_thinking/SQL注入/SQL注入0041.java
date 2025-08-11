package com.example.security.demo.controller;

import com.example.security.demo.service.UserService;
import com.example.security.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户管理Controller
 * @author security team
 */
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public List<User> listUsers(@RequestParam(required = false) String username,
                                 @RequestParam(required = false) String mobile,
                                 @RequestParam(defaultValue = "1") int pageNum,
                                 @RequestParam(defaultValue = "10") int pageSize,
                                 @RequestParam(defaultValue = "username") String sort,
                                 @RequestParam(defaultValue = "asc") String order) {
        
        // 对用户名进行长度校验（看似安全的防护措施）
        if (username != null && username.length() > 50) {
            throw new IllegalArgumentException("用户名过长");
        }
        
        // 将排序参数直接传递给服务层（危险的参数传递方式）
        return userService.getUsers(username, mobile, pageNum, pageSize, sort, order);
    }
}

package com.example.security.demo.service;

import com.example.security.demo.mapper.UserMapper;
import com.example.security.demo.model.User;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 用户服务实现
 * @author security team
 */
@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> getUsers(String username, String mobile, int pageNum, int pageSize, String sort, String order) {
        Page<User> page = new Page<>(pageNum, pageSize);
        
        // 构造动态查询条件（存在漏洞的关键点）
        StringBuilder condition = new StringBuilder("1=1");
        
        if (username != null && !username.isEmpty()) {
            condition.append(" AND username LIKE '%").append(username).append("%'");
        }
        
        if (mobile != null && !mobile.isEmpty()) {
            condition.append(" AND mobile LIKE '%").append(mobile).append("%'");
        }
        
        // 危险的ORDER BY拼接（SQL注入点）
        if (sort != null && !sort.isEmpty() && order != null && !order.isEmpty()) {
            // 表面的白名单检查（存在绕过可能）
            if (sort.matches("[a-zA-Z0-9_]+")) {
                page.setOrderBy(sort + " " + order);
            }
        }
        
        // 执行分页查询（使用MyBatis Plus的lambda查询）
        return userMapper.selectPage(page, condition.toString());
    }
}

package com.example.security.demo.mapper;

import com.example.security.demo.model.User;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 用户数据访问接口
 * @author security team
 */
public interface UserMapper extends BaseMapper<User> {
    List<User> selectPage(@Param("page") Page<User> page, @Param("condition") String condition);
}

// Mapper XML 文件
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.security.demo.mapper.UserMapper">
  <select id="selectPage" resultType="com.example.security.demo.model.User">
    SELECT * FROM users
    <where>
      ${condition} <!-- 使用$符号进行字符串替换（危险操作） -->
    </where>
    <if test="page.orderBy != null and page.orderBy != ''">
      ORDER BY ${page.orderBy} <!-- 这里再次使用危险的字符串替换 -->
    </if>
  </select>
</mapper>