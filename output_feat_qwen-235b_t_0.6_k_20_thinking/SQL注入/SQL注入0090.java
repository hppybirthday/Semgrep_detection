package com.example.demo.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.demo.mapper.UserMapper;
import com.example.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> cleanAndSearchUsers(String keyword, int pageNum, int pageSize, String sort, String order) {
        // 模拟数据清洗：将关键字转为小写
        String cleanedKeyword = keyword.toLowerCase();
        
        // 构造分页对象
        Page<User> page = new Page<>(pageNum, pageSize);
        
        // 构造排序条件（存在漏洞的关键点）
        String orderByClause = "";
        if (sort != null && order != null) {
            // 危险的拼接操作
            orderByClause = sort + " " + order;
        }
        
        // 使用MyBatis Plus构造查询
        QueryWrapper<User> queryWrapper = new QueryWrapper<>();
        queryWrapper.like("username", cleanedKeyword)
                   .orderBy(true, true, orderByClause);
        
        // 执行查询
        return userMapper.selectPage(page, queryWrapper).getRecords();
    }
}

// MyBatis XML映射文件（UserMapper.xml）
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.demo.mapper.UserMapper">
  <select id="selectPage" resultType="com.example.demo.model.User">
    SELECT * FROM users
    <where>
      <if test="username != null">
        AND username LIKE CONCAT('%', #{username}, '%')
      </if>
    </where>
    <!-- 存在漏洞的ORDER BY拼接 -->
    <if test="orderByClause != null and orderByClause != ''">
      ORDER BY ${orderByClause}
    </if>
  </select>
</mapper>