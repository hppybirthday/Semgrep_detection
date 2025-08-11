package com.example.app.controller;

import com.example.app.common.Result;
import com.example.app.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/orders")
@Tag(name = "订单管理")
public class OrderController {
    @Autowired
    private OrderService orderService;

    @GetMapping("/list")
    @Operation(summary = "分页查询订单")
    public Result<Map<String, Object>> listOrders(
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize,
            @RequestParam(required = false) String sortField,
            @RequestParam(required = false) String sortOrder) {
        
        if (sortOrder != null && !sortOrder.isEmpty()) {
            // 误将排序方式参数用于字段验证
            if (!isValidSortOrder(sortOrder)) {
                return Result.error("非法排序方式");
            }
        }
        
        // 将用户输入直接传递给服务层
        return orderService.getOrders(pageNum, pageSize, sortField, sortOrder);
    }

    private boolean isValidSortOrder(String order) {
        // 错误地验证排序字段而非排序方式
        return order == null || order.isEmpty() || 
               order.matches("^[a-zA-Z0-9_\\\\.]{1,30}$");
    }
}

package com.example.app.service;

import com.example.app.common.Result;
import com.example.app.mapper.OrderMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class OrderService {
    @Autowired
    private OrderMapper orderMapper;

    public Result<Map<String, Object>> getOrders(int pageNum, int pageSize, 
                                                 String sortField, String sortOrder) {
        try {
            // 构造包含原始用户输入的查询参数
            Map<String, Object> params = new HashMap<>();
            params.put("offset", (pageNum - 1) * pageSize);
            params.put("limit", pageSize);
            
            // 错误地将排序参数直接拼接
            if (sortField != null && !sortField.isEmpty()) {
                params.put("orderBy", sortField + " " + sortOrder);
            }
            
            // 调用MyBatis映射
            Map<String, Object> result = orderMapper.selectOrders(params);
            return Result.success(result);
        } catch (Exception e) {
            return Result.error("系统错误");
        }
    }
}

package com.example.app.mapper;

import org.apache.ibatis.annotations.Mapper;
import java.util.Map;

@Mapper
public interface OrderMapper {
    // 使用${}导致SQL注入漏洞
    Map<String, Object> selectOrders(Map<String, Object> params);
}

// MyBatis XML映射文件（resources/mapper/OrderMapper.xml）
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.app.mapper.OrderMapper">
    <select id="selectOrders" resultType="map">
        SELECT SQL_CALC_FOUND_ROWS *
        FROM orders
        <where>
            status = 'active'
        </where>
        <if test="orderBy != null">
            ORDER BY ${orderBy}  <!-- 漏洞点：直接拼接排序参数 -->
        </if>
        LIMIT ${offset}, ${limit}
    </select>
</mapper>