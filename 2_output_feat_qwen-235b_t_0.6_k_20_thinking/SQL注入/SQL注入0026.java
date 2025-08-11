package com.example.order.controller;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.order.dto.OrderQueryDTO;
import com.example.order.model.Order;
import com.example.order.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 订单查询管理Controller
 * Created by devteam on 2023/08/20.
 */
@RestController
@Tag(name = "OrderQueryController", description = "订单查询管理")
@RequestMapping("/order/query")
public class OrderQueryController {
    @Autowired
    private OrderService orderService;

    @Operation(summary = "分页查询订单")
    @GetMapping("/list")
    public IPage<Order> list(@Parameter(description = "页码") @RequestParam int pageNum,
                             @Parameter(description = "每页数量") @RequestParam int pageSize,
                             @Parameter(description = "排序字段") @RequestParam(required = false) String sort,
                             @Parameter(description = "排序方式") @RequestParam(required = false) String order) {
        return orderService.queryOrders(pageNum, pageSize, sort, order);
    }
}

// Service层实现
package com.example.order.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.order.mapper.OrderMapper;
import com.example.order.model.Order;
import com.example.order.service.OrderService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class OrderServiceImpl implements OrderService {
    @Autowired
    private OrderMapper orderMapper;

    @Override
    public IPage<Order> queryOrders(int pageNum, int pageSize, String sort, String order) {
        Page<Order> page = new Page<>(pageNum, pageSize);
        
        // 构建动态查询条件
        LambdaQueryWrapper<Order> queryWrapper = new LambdaQueryWrapper<>();
        
        // 添加业务时间范围过滤
        Date threeMonthsAgo = new Date(System.currentTimeMillis() - 90L * 24 * 3600 * 1000);
        queryWrapper.ge(Order::getCreateTime, threeMonthsAgo);
        
        // 构建动态排序条件
        if (StringUtils.isNotBlank(sort) && StringUtils.isNotBlank(order)) {
            String sortClause = sort + " " + order;
            // 错误使用字符串拼接构建排序条件（存在SQL注入）
            queryWrapper.last("ORDER BY " + sortClause);
        }
        
        return orderMapper.selectPage(page, queryWrapper);
    }
}

// Mapper接口
package com.example.order.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.order.model.Order;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface OrderMapper extends BaseMapper<Order> {
}