package com.chat.app.controller;

import com.chat.app.service.UserService;
import com.chat.app.dto.UserQueryDTO;
import com.chat.app.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/list")
    public ApiResponse<List<User>> getUsers(@RequestParam String roleCodes, 
                                             @RequestParam int pageNum, 
                                             @RequestParam int pageSize) {
        // 校验分页参数
        if (pageNum <= 0 || pageSize <= 0) {
            return ApiResponse.fail("分页参数无效");
        }
        
        // 构造查询条件
        UserQueryDTO queryDTO = new UserQueryDTO();
        queryDTO.setRoleCodes(roleCodes);
        queryDTO.setPageNum(pageNum);
        queryDTO.setPageSize(pageSize);
        
        return ApiResponse.success(userService.getUsersByRole(queryDTO));
    }
}

// -------------------------------------
// com/chat/app/service/UserService.java
package com.chat.app.service;

import com.chat.app.mapper.UserMapper;
import com.chat.app.dto.UserQueryDTO;
import com.chat.app.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> getUsersByRole(UserQueryDTO queryDTO) {
        // 处理排序字段（安全校验）
        String sortField = "create_time";
        if (queryDTO.getRoleCodes() != null && !queryDTO.getRoleCodes().isEmpty()) {
            sortField = "role_code";
        }
        
        // 调用持久层
        return userMapper.selectUsers(
            queryDTO.getRoleCodes(),
            (queryDTO.getPageNum() - 1) * queryDTO.getPageSize(),
            queryDTO.getPageSize(),
            sortField
        );
    }
}

// -------------------------------------
// com/chat/app/mapper/UserMapper.java
package com.chat.app.mapper;

import com.chat.app.model.User;
import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface UserMapper {
    List<User> selectUsers(@Param("roleCodes") String roleCodes,
                          @Param("offset") int offset,
                          @Param("limit") int limit,
                          @Param("sortField") String sortField);
}

// -------------------------------------
// resources/mapper/UserMapper.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.chat.app.mapper.UserMapper">
    <select id="selectUsers" resultType="com.chat.app.model.User">
        SELECT * FROM users
        <where>
            <if test="roleCodes != null and roleCodes != ''">
                AND role_code IN
                <foreach item="code" collection="roleCodes" open="(" separator="," close=")">
                    #{code}
                </foreach>
            </if>
        </where>
        ORDER BY ${sortField} DESC
        LIMIT #{offset}, #{limit}
    </select>
</mapper>