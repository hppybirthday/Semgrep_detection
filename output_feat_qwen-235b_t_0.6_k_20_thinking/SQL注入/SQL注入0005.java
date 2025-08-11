package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import java.lang.reflect.Field;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class SqlInjectionDemo {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemo.class, args);
    }

    @GetMapping("/list")
    public Object listUsers(@RequestParam String username, @RequestParam String mobile, 
                           @RequestParam String sort, @RequestParam String order) {
        QueryWrapper<User> wrapper = new QueryWrapper<>();
        if (username != null) wrapper.like("username", username);
        if (mobile != null) wrapper.like("mobile", mobile);
        
        // 漏洞点：动态拼接ORDER BY子句
        Page<User> page = new Page<>(1, 10);
        try {
            Field orderByField = Page.class.getDeclaredField("orderByField");
            orderByField.setAccessible(true);
            // 危险操作：直接拼接用户输入
            orderByField.set(page, sort + " " + order);
        } catch (Exception e) {
            return "error";
        }
        
        return UserMapper.selectPage(page, wrapper);
    }

    @GetMapping("/detail")
    public Object getUserDetail(@RequestParam String id) {
        // 漏洞点：直接拼接ID参数
        return UserMapper.selectOne(new QueryWrapper<User>().eq("id", id));
    }

    // MyBatis Mapper
    public interface UserMapper extends com.baomidou.mybatisplus.core.mapper.BaseMapper<User> {
        // 漏洞SQL示例（实际在MyBatis XML中）
        // <select id="selectPage" resultType="User">
        //   SELECT * FROM users
        //   <where>
        //     <if test="username != null">
        //       AND username LIKE CONCAT('%', #{username}, '%')
        //     </if>
        //   </where>
        //   ORDER BY ${orderByField}  <!-- 不安全的写法 -->
        // </select>
    }

    // 实体类
    public static class User {
        private String id;
        private String username;
        private String mobile;
        // getter/setter
    }
}