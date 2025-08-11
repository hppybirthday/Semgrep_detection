package com.example.demo.user;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

@Service
public class UserService extends ServiceImpl<UserMapper, User> {
    public boolean deleteUsers(String ids) {
        // 漏洞点：直接将用户输入拼接到查询条件中
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.in("id", ids.split(","));
        return remove(wrapper);
    }
}

// Mapper层
package com.example.demo.user;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {
    // MyBatis-Plus底层实现中，in条件会使用${}拼接ID列表（实际测试中发现）
}

// Controller层
package com.example.demo.user;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @DeleteMapping("/{ids}")
    public String deleteUsers(@PathVariable String ids) {
        // 漏洞触发：恶意输入如 "1,2); DROP TABLE users;--"
        boolean result = userService.deleteUsers(ids);
        return result ? "Deleted" : "Failed";
    }
}

// 实体类
package com.example.demo.user;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

@Data
@TableName("users")
public class User {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String username;
    private String email;
}

// MyBatis配置（模拟实际环境）
// 实际环境中会通过MyBatis-Plus自动构建SQL，其底层实现可能在特定场景下生成不安全的SQL语句
// 例如生成的SQL可能为：DELETE FROM users WHERE id IN (${ids}) （使用${}而非#{}）