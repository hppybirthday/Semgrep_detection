package com.example.order.controller;

import com.example.order.service.OrderService;
import com.example.order.dto.OrderDTO;
import com.example.common.utils.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @Autowired
    private OrderService orderService;

    @GetMapping
    @ApiOperation("分页查询订单")
    public Result<List<OrderDTO>> getOrders(@RequestParam(required = false) String productName,
                                            @RequestParam(defaultValue = "1") int pageNum,
                                            @RequestParam(defaultValue = "10") int pageSize,
                                            @RequestParam(defaultValue = "id_desc") String sortBy) {
        return Result.ok(orderService.getOrders(productName, pageNum, pageSize, sortBy));
    }
}

package com.example.order.service;

import com.example.order.dto.OrderDTO;
import com.example.order.mapper.OrderMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class OrderServiceImpl implements OrderService {
    @Autowired
    private OrderMapper orderMapper;

    @Override
    public List<OrderDTO> getOrders(String productName, int pageNum, int pageSize, String sortBy) {
        validateSortParam(sortBy);
        int offset = (pageNum - 1) * pageSize;
        return orderMapper.selectOrders(productName, offset, pageSize, sortBy);
    }

    private void validateSortParam(String sortBy) {
        if (sortBy != null && !sortBy.matches("^[a-zA-Z0-9_\\s,]+$")) {
            throw new IllegalArgumentException("Invalid sort parameter");
        }
    }
}

package com.example.order.mapper;

import com.example.order.dto.OrderDTO;
import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface OrderMapper {
    List<OrderDTO> selectOrders(@Param("productName") String productName,
                               @Param("offset") int offset,
                               @Param("limit") int pageSize,
                               @Param("sortBy") String sortBy);
}

// MyBatis XML映射文件
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.order.mapper.OrderMapper">
    <select id="selectOrders" resultType="com.example.order.dto.OrderDTO">
        SELECT * FROM orders
        <where>
            <if test="productName != null and productName != ''">
                AND product_name LIKE '%${productName}%'
            </if>
        </where>
        ORDER BY ${sortBy}
        LIMIT ${offset}, ${limit}
    </select>
</mapper>