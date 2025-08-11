package com.example.order.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.order.entity.Order;
import com.example.order.mapper.OrderMapper;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;

@Service
public class OrderService extends ServiceImpl<OrderMapper, Order> {
    
    public Page<Order> getOrdersWithSorting(int pageNum, int pageSize, String sortField, String sortOrder) {
        // 漏洞点：直接拼接排序参数
        String orderByClause = "";
        if (StringUtils.hasText(sortField) && StringUtils.hasText(sortOrder)) {
            orderByClause = sortField + " " + sortOrder;
        }
        
        // 使用PageHelper进行分页排序
        Page<Order> page = new Page<>(pageNum, pageSize);
        page.setOrderBy(orderByClause);
        
        // 构造查询条件
        QueryWrapper<Order> queryWrapper = new QueryWrapper<>();
        return this.page(page, queryWrapper);
    }
    
    public List<Order> getAllOrders() {
        return this.list();
    }
}

// --------------------------------------
// Mapper层
package com.example.order.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.order.entity.Order;
import java.util.List;

public interface OrderMapper extends BaseMapper<Order> {
    // 使用MyBatis Plus自动生成的CRUD方法
}

// --------------------------------------
// Controller层
package com.example.order.controller;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.order.entity.Order;
import com.example.order.service.OrderService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/orders")
public class OrderController {
    
    private final OrderService orderService;
    
    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }
    
    @GetMapping
    public Page<Order> getOrders(
        @RequestParam int pageNum,
        @RequestParam int pageSize,
        @RequestParam(required = false) String sortField,
        @RequestParam(required = false) String sortOrder) {
        
        return orderService.getOrdersWithSorting(pageNum, pageSize, sortField, sortOrder);
    }
}

// --------------------------------------
// 实体类
package com.example.order.entity;

import lombok.Data;
import java.math.BigDecimal;

@Data
public class Order {
    private Long id;
    private String orderNo;
    private BigDecimal amount;
    private String status;
    private String customerName;
}