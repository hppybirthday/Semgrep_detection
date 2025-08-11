package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.apache.ibatis.annotations.*;
import java.util.*;

@SpringBootApplication
@MapperScan("com.example.demo.mapper")
public class SqlInjectionDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public List<User> getUsers(@RequestParam String id,
                               @RequestParam(required = false) String sort,
                               @RequestParam(required = false) String order) {
        return userService.findUsers(id, sort, order);
    }
}

@Service
class UserService {
    private final UserMapper userMapper;

    public UserService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public List<User> findUsers(String id, String sort, String order) {
        return userMapper.selectWithParams(id, sort, order);
    }
}

@Mapper
interface UserMapper {
    @Select({"<script>",
        "SELECT * FROM users WHERE id = ${id}",
        "<if test='sort != null and order != null'>",
        "ORDER BY ${sort} ${order}",
        "</if>",
        "</script>"})
    @Results({
        @Result(property = "id", column = "id"),
        @Result(property = "name", column = "name")
    })
    List<User> selectWithParams(@Param("id") String id,
                                @Param("sort") String sort,
                                @Param("order") String order);
}

record User(Long id, String name) {}

// MyBatis XML配置（实际应放在resources/mapper/UserMapper.xml）
/*
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.demo.mapper.UserMapper">
    <select id="selectWithParams" resultType="com.example.demo.User">
        SELECT * FROM users 
        WHERE id = ${id}
        <if test="sort != null and order != null">
            ORDER BY ${sort} ${order}
        </if>
    </select>
</mapper>
*/