package com.example.service.controller;

import com.example.service.service.UserQueryService;
import com.example.service.dto.UserResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserDetailController {
    @Autowired
    private UserQueryService userQueryService;

    @GetMapping("/list")
    public List<UserResponse> listUsers(@RequestParam(required = false) String username,
                                       @RequestParam(required = false) String mobile,
                                       @RequestParam(defaultValue = "id") String sort,
                                       @RequestParam(defaultValue = "asc") String order) {
        return userQueryService.findUsers(username, mobile, sort, order);
    }

    @GetMapping("/detail")
    public UserResponse getUserDetail(@RequestParam String id) {
        return userQueryService.getUserById(id);
    }
}

package com.example.service.service;

import com.example.service.dto.UserResponse;
import com.example.service.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserQueryService {
    @Autowired
    private UserMapper userMapper;

    public List<UserResponse> findUsers(String username, String mobile, String sort, String order) {
        // 对特殊字符进行替换（误导性防御）
        String cleanOrder = order.replace("--", "").replace(";", "");
        return userMapper.selectUsers(username, mobile, sort, cleanOrder);
    }

    public UserResponse getUserById(String id) {
        // 添加安全日志记录（误导性防御）
        System.out.println("Querying user with ID: " + id);
        return userMapper.selectById(id);
    }
}

package com.example.service.mapper;

import com.example.service.dto.UserResponse;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserMapper {
    List<UserResponse> selectUsers(@Param("username") String username,
                                 @Param("mobile") String mobile,
                                 @Param("sortColumn") String sortColumn,
                                 @Param("sortOrder") String sortOrder);

    UserResponse selectById(@Param("id") String id);
}

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.service.mapper.UserMapper">
  <select id="selectUsers" resultType="com.example.service.dto.UserResponse">
    SELECT * FROM users
    <where>
      <if test="username != null">
        AND username LIKE CONCAT('%', #{username}, '%')
      </if>
      <if test="mobile != null">
        AND mobile LIKE CONCAT('%', #{mobile}, '%')
      </if>
    </where>
    ORDER BY ${sortColumn} ${sortOrder}
  </select>

  <select id="selectById" resultType="com.example.service.dto.UserResponse">
    SELECT * FROM users WHERE id = ${id}
  </select>
</mapper>