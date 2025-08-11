package com.example.crawler.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.IService;
import com.example.crawler.model.UserFavorite;
import com.example.crawler.service.UserFavoriteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.regex.Pattern;

/**
 * 用户收藏管理Controller
 * 提供基于爬虫数据的收藏列表查询接口
 */
@RestController
@RequestMapping("/favorites")
public class UserFavoriteController {
    @Autowired
    private UserFavoriteService favoriteService;

    /**
     * 分页查询用户收藏列表（含排序功能）
     * 攻击面：通过fieldName参数注入ORDER BY子句
     */
    @GetMapping("/list")
    public IPage<UserFavorite> getFavorites(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String fieldName,
            @RequestParam(defaultValue = "asc") String order) {
        
        // 表面的安全过滤（存在绕过可能）
        if (fieldName != null && !isValidFieldName(fieldName)) {
            throw new IllegalArgumentException("Invalid field name");
        }
        
        // 构造分页对象
        Page<UserFavorite> page = new Page<>(pageNum, pageSize);
        
        // 漏洞点：直接拼接ORDER BY子句
        String orderByClause = fieldName != null ? 
            fieldName + " " + order : "create_time desc";
        
        // 使用MyBatis Plus动态SQL拼接（危险操作）
        return favoriteService.page(page, new QueryWrapper<UserFavorite>()
            .orderBySql(orderByClause));
    }

    /**
     * 简单的字段名校验（存在正则绕过可能）
     */
    private boolean isValidFieldName(String name) {
        return Pattern.matches("^[a-zA-Z0-9_]{1,32}$", name);
    }
}

// Service层代码
package com.example.crawler.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.crawler.model.UserFavorite;
import org.springframework.stereotype.Service;

@Service
public class UserFavoriteService extends IService<UserFavorite> {
    // MyBatis Plus自动注入Mapper
}

// Mapper XML文件
<!-- UserFavoriteMapper.xml -->
<mapper namespace="com.example.crawler.mapper.UserFavoriteMapper">
    <select id="selectPage" resultType="com.example.crawler.model.UserFavorite">
        SELECT *
        FROM user_favorites
        <where>
            status = 1
        </where>
        <if test="ew.sqlSegment != null">
            ORDER BY ${ew.sqlSegment}
        </if>
    </select>
</mapper>

// 实体类
package com.example.crawler.model;

import lombok.Data;

/**
 * 用户收藏实体类
 */
@Data
public class UserFavorite {
    private Long id;
    private Long userId;
    private String contentUrl;
    private String title;
    private Integer status;
    private Long createTime;
}