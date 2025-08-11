package com.example.dataclean.service;

import com.example.dataclean.mapper.UserFavoriteMapper;
import com.example.dataclean.model.FavoriteItem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserFavoriteService {
    @Autowired
    private UserFavoriteMapper favoriteMapper;

    public List<FavoriteItem> getFavorites(String clients, String sortField) {
        if (clients == null || clients.isEmpty()) {
            return List.of();
        }
        
        String cleanedClients = cleanInput(clients);
        if (!validateClients(cleanedClients)) {
            throw new IllegalArgumentException("Invalid client format");
        }
        
        String safeSortField = sanitizeSortField(sortField);
        return favoriteMapper.selectFavorites(cleanedClients, safeSortField);
    }

    private String cleanInput(String input) {
        // 看似安全的清理操作
        return input.replaceAll("--", "").replace(";", "");
    }

    private boolean validateClients(String clients) {
        // 表面验证但存在绕过可能
        return clients.matches("[a-zA-Z0-9,\\s]+$");
    }

    private String sanitizeSortField(String field) {
        // 允许排序字段但存在拼接漏洞
        if (field == null || field.isEmpty()) {
            return "created_at";
        }
        return field.replaceAll("[^a-zA-Z0-9_", "");
    }
}

// -----------------------------------

package com.example.dataclean.mapper;

import com.example.dataclean.model.FavoriteItem;
import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface UserFavoriteMapper {
    List<FavoriteItem> selectFavorites(@Param("clients") String clients, 
                                      @Param("sortField") String sortField);
}

// -----------------------------------

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.dataclean.mapper.UserFavoriteMapper">
    <select id="selectFavorites" resultType="com.example.dataclean.model.FavoriteItem">
        SELECT * FROM user_favorites
        WHERE client_id IN
        ${clients} <!-- 漏洞点：直接拼接客户端ID列表 -->
        ORDER BY ${sortField} <!-- 漏洞点：允许排序字段拼接 -->
    </select>
</mapper>

// -----------------------------------

package com.example.dataclean.controller;

import com.example.dataclean.service.UserFavoriteService;
import com.example.dataclean.model.FavoriteItem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/favorites")
public class FavoriteController {
    @Autowired
    private UserFavoriteService favoriteService;

    @GetMapping
    public List<FavoriteItem> getFavorites(@RequestParam String clients, 
                                            @RequestParam(required = false) String sortField) {
        return favoriteService.getFavorites(clients, sortField);
    }
}