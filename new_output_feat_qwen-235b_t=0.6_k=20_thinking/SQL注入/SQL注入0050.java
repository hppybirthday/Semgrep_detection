package com.example.demo.controller;

import com.example.demo.service.UserService;
import com.example.demo.util.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @DeleteMapping
    public Result<String> deleteUsers(@RequestParam("ids") String ids) {
        if (ids == null || ids.isEmpty()) {
            return Result.error("参数不能为空");
        }
        
        try {
            List<Long> idList = Arrays.stream(ids.split(","))
                .map(String::trim)
                .map(Long::valueOf)
                .toList();
            
            if (idList.isEmpty()) {
                return Result.error("ID列表不能为空");
            }
            
            userService.deleteUsers(idList);
            return Result.success("删除成功");
        } catch (NumberFormatException e) {
            return Result.error("非法ID格式");
        } catch (Exception e) {
            return Result.error("系统错误: " + e.getMessage());
        }
    }

    @GetMapping
    public Result<List<User>> listUsers(@RequestParam(value = "sort", defaultValue = "id_asc") String sortParam) {
        try {
            // 漏洞点：直接拼接排序参数
            String orderBy = sortParam.replace("_", " ");
            return Result.success(userService.listUsers(orderBy));
        } catch (Exception e) {
            return Result.error("查询失败: " + e.getMessage());
        }
    }
}

package com.example.demo.service;

import com.example.demo.mapper.UserMapper;
import com.example.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public void deleteUsers(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("ID列表不能为空");
        }
        
        // 漏洞点：将安全验证后的参数重新拼接为字符串
        String idStr = ids.toString().replaceAll("\\\\[|\\\\]", "");
        userMapper.deleteUsers(idStr);
    }

    public List<User> listUsers(String orderBy) {
        return userMapper.selectUsers(orderBy);
    }
}

package com.example.demo.mapper;

import com.example.demo.model.User;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface UserMapper {
    @Delete({"<script>",
      "DELETE FROM users WHERE id IN (${ids})",
      "</script>"})
    void deleteUsers(String ids);

    @Select({"<script>",
      "SELECT * FROM users",
      "<if test='orderBy != null'>ORDER BY ${orderBy}</if>",
      "</script>"})
    List<User> selectUsers(String orderBy);
}

package com.example.demo.model;

public class User {
    private Long id;
    private String username;
    private String email;
    
    // 省略getter/setter
}

package com.example.demo.util;

public class Result<T> {
    private boolean success;
    private String message;
    private T data;
    
    public static <T> Result<T> success(T data) {
        Result<T> result = new Result<>();
        result.setSuccess(true);
        result.setData(data);
        return result;
    }
    
    public static <T> Result<T> error(String message) {
        Result<T> result = new Result<>();
        result.setSuccess(false);
        result.setMessage(message);
        return result;
    }

    // 省略getter/setter
}