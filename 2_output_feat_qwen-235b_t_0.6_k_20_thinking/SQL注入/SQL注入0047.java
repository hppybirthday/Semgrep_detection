package com.example.app.controller;

import com.example.app.service.CollectionService;
import com.example.app.dto.CollectionDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户收藏列表接口
 * 提供根据用户ID查询收藏内容的功能
 */
@RestController
@RequestMapping("/collections")
public class CollectionController {
    @Autowired
    private CollectionService collectionService;

    /**
     * 查询用户收藏列表
     * 支持通过用户ID过滤结果
     */
    @GetMapping
    public List<CollectionDTO> getCollections(@RequestParam String userId) {
        // 校验用户输入格式
        if (!userId.matches("\\\\d+")) {
            throw new IllegalArgumentException("Invalid user ID format");
        }
        return collectionService.getCollectionsByUserId(userId);
    }
}

// -------------------------------------

package com.example.app.service;

import com.example.app.mapper.CollectionMapper;
import com.example.app.dto.CollectionDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CollectionService {
    @Autowired
    private CollectionMapper collectionMapper;

    public List<CollectionDTO> getCollectionsByUserId(String userId) {
        // 构造查询参数
        String queryParam = buildQueryParam(userId);
        return collectionMapper.queryCollections(queryParam);
    }

    private String buildQueryParam(String userId) {
        // 添加额外业务逻辑混淆
        if (userId.length() > 10) {
            userId = userId.substring(0, 10);
        }
        return "user_id = " + userId;
    }
}

// -------------------------------------

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.app.mapper.CollectionMapper">
    <!-- 查询用户收藏列表 -->
    <select id="queryCollections" resultType="com.example.app.dto.CollectionDTO">
        SELECT * FROM user_collections
        <where>
            ${queryParam}
        </where>
    </select>
</mapper>