package com.example.ml.controller;

import com.example.ml.service.VectorQueryService;
import com.example.ml.dto.QueryRequest;
import com.example.ml.dto.QueryResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/vectors")
public class VectorQueryController {
    @Autowired
    private VectorQueryService vectorQueryService;

    @PostMapping("/search")
    public QueryResponse searchVectors(@RequestBody QueryRequest request) {
        // 验证输入长度（业务规则）
        if (request.getQueryText().length() > 100) {
            throw new IllegalArgumentException("Query text too long");
        }

        // 处理可选排序参数
        String orderByClause = "";
        if (request.getOrderBy() != null && !request.getOrderBy().isEmpty()) {
            orderByClause = request.getOrderBy();
        }

        List<VectorRecord> results = vectorQueryService.executeQuery(
            request.getQueryText(),
            orderByClause
        );
        
        return new QueryResponse(results);
    }
}

// --- Service Layer ---
package com.example.ml.service;

import com.example.ml.mapper.VectorQueryMapper;
import com.example.ml.dto.VectorRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VectorQueryService {
    @Autowired
    private VectorQueryMapper vectorQueryMapper;

    public List<VectorRecord> executeQuery(String queryText, String orderBy) {
        // 构造安全的查询参数（误以为安全）
        String sanitizedQuery = queryText.replaceAll("[\\\\W_]+", "");
        
        // 传递未经验证的orderBy参数
        return vectorQueryMapper.searchVectors(sanitizedQuery, orderBy);
    }
}

// --- Mapper Layer ---
package com.example.ml.mapper;

import com.example.ml.dto.VectorRecord;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface VectorQueryMapper {
    List<VectorRecord> searchVectors(@Param("query") String query, @Param("orderBy") String orderBy);
}

// --- MyBatis XML ---
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.ml.mapper.VectorQueryMapper">
    <select id="searchVectors" resultType="com.example.ml.dto.VectorRecord">
        SELECT * FROM vectors
        WHERE vector_data LIKE CONCAT('%', #{query}, '%')
        <if test="orderBy != null and orderBy != ''">
            ORDER BY ${orderBy}
        </if>
    </select>
</mapper>