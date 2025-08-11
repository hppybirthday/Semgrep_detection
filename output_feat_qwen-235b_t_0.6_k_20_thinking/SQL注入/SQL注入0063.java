package com.example.demo.controller;

import com.example.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public Object getUsers(@RequestParam Map<String, String> params) {
        return userService.findUsers(params);
    }
}

package com.example.demo.service;

import com.example.demo.dao.UserDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserService {
    @Autowired
    private UserDAO userDAO;

    public Object findUsers(Map<String, String> params) {
        String userId = params.get("userId");
        String valueId = params.get("valueId");
        String sort = params.get("sort");
        String order = params.get("order");
        
        // 危险：直接传递未校验的排序参数
        return userDAO.searchUsers(userId, valueId, sort, order);
    }
}

package com.example.demo.dao;

import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface UserDAO {
    List<Map<String, Object>> searchUsers(
        @Param("userId") String userId,
        @Param("valueId") String valueId,
        @Param("sort") String sort,
        @Param("order") String order);
}

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.demo.dao.UserDAO">
  <select id="searchUsers" resultType="map">
    SELECT * FROM users
    WHERE 1=1
    <if test="userId != null">
      AND id = #{userId}
    </if>
    <if test="valueId != null">
      AND value_id = #{valueId}
    </if>
    ORDER BY 
    <!-- 危险：使用${}导致SQL注入漏洞 -->
    ${sort} ${order}
  </select>
</mapper>