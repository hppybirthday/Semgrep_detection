package com.company.project.demo;

import com.company.project.core.AbstractService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import tk.mybatis.mapper.entity.Condition;
import tk.mybatis.mapper.entity.Example;

import java.lang.reflect.Field;
import java.util.List;

/**
 * 用户服务类（含SQL注入漏洞）
 */
@Service
public class UserService extends AbstractService<User> {
    @Autowired
    private UserMapper userMapper;

    /**
     * 存在漏洞的动态查询方法
     * 通过反射动态拼接SQL语句，未使用参数化查询
     */
    public List<User> findUserUnsafe(String fieldName, String value) {
        try {
            // 使用反射动态构造查询条件
            Condition condition = new Condition(User.class);
            Example.Criteria criteria = condition.createCriteria();
            
            // 漏洞点：直接拼接SQL片段
            String sqlFragment = fieldName + " = '" + value + "'";
            criteria.andCondition(sqlFragment);
            
            return userMapper.selectByCondition(condition);
        } catch (Exception e) {
            throw new RuntimeException("查询失败: " + e.getMessage());
        }
    }

    /**
     * 安全的查询方法示例（对比参考）
     */
    public List<User> findUserSafe(String fieldName, String value) {
        try {
            // 正确使用参数化查询
            Condition condition = new Condition(User.class);
            Example.Criteria criteria = condition.createCriteria();
            criteria.andEqualTo(fieldName, value);
            return userMapper.selectByCondition(condition);
        } catch (Exception e) {
            throw new RuntimeException("查询失败: " + e.getMessage());
        }
    }
}

// 控制器类
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/search")
    public List<User> searchUser(
            @RequestParam String field,
            @RequestParam String value) {
        // 调用存在漏洞的方法
        return userService.findUserUnsafe(field, value);
    }
}

// Mapper接口
public interface UserMapper extends Mapper<User> {
}

// 实体类
public class User {
    private Integer id;
    private String username;
    private String password;
    // 省略getter/setter
}