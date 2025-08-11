package com.example.bank.user;

import org.apache.ibatis.annotations.*;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// Controller层
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @DeleteMapping("/{ids}")
    public String deleteUser(@PathVariable String ids) {
        // 漏洞点：未校验ids参数直接传递给服务层
        userService.removeByIds(ids);
        return "Deleted";
    }

    @GetMapping
    public PageInfo<User> listUsers(@RequestParam(required = false) String orderParams) {
        // 漏洞点：orderParams直接用于PageHelper动态拼接
        if (orderParams != null && !orderParams.isEmpty()) {
            PageHelper.orderBy(orderParams); // 元编程风格的动态SQL构造
        }
        return new PageInfo<>(userService.list());
    }
}

// Service层
@Service
class UserService {
    @Autowired
    private UserMapper userMapper;

    public void removeByIds(String ids) {
        // 漏洞点：直接拼接SQL
        userMapper.deleteByIds(ids);
    }
}

// Mapper层
@Mapper
interface UserMapper extends BaseMapper<User> {
    @Select("SELECT * FROM users WHERE id IN (${ids})")
    @Delete("DELETE FROM users WHERE id IN (${ids})")
    void deleteByIds(String ids);
}

// 实体类
class User {
    private Long id;
    private String username;
    private Double balance;
    // 省略getter/setter
}