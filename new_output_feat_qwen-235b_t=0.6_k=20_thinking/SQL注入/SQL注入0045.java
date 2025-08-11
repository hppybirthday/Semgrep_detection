package com.example.app.controller;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.app.model.UserOrder;
import com.example.app.service.UserOrderService;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 订单管理Controller
 * @author developer
 */
@RestController
@RequestMapping("/api/order")
public class UserOrderController {
    @Autowired
    private UserOrderService orderService;

    /**
     * 分页查询订单
     * 支持按用户ID和订单状态过滤，支持动态排序
     */
    @GetMapping("/list")
    public PageInfo<UserOrder> listOrders(@RequestParam(defaultValue = "1") int pageNum,
                                          @RequestParam(defaultValue = "10") int pageSize,
                                          @RequestParam(required = false) String userId,
                                          @RequestParam(required = false) String status,
                                          @RequestParam(required = false) String sortBy) {
        // 初始化分页参数
        Page<UserOrder> page = new Page<>(pageNum, pageSize);
        
        // 处理排序逻辑
        if (sortBy != null && !sortBy.isEmpty()) {
            // 验证排序字段合法性（看似安全但存在缺陷）
            if (validateSortColumn(sortBy)) {
                PageHelper.orderBy(sortBy);  // 危险操作：直接拼接排序参数
            }
        }
        
        // 执行查询
        return orderService.getOrders(page, userId, status);
    }

    /**
     * 验证排序字段是否合法（存在逻辑缺陷）
     * 仅允许特定列名，但可通过闭合括号绕过
     */
    private boolean validateSortColumn(String column) {
        String[] allowedColumns = {"create_time", "amount", "status"};
        for (String col : allowedColumns) {
            if (column.contains(col)) {
                return true;
            }
        }
        return false;
    }
}

package com.example.app.service;

import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.app.model.UserOrder;
import com.example.app.mapper.UserOrderMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserOrderService {
    @Autowired
    private UserOrderMapper orderMapper;

    public IPage<UserOrder> getOrders(Page<UserOrder> page, String userId, String status) {
        // 构造查询条件
        return orderMapper.selectPage(page, userId, status);
    }
}

package com.example.app.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import org.apache.ibatis.annotations.Param;
import java.util.Map;

public interface UserOrderMapper extends BaseMapper<UserOrder> {
    /**
     * 自定义分页查询
     * 使用MyBatis Plus的动态SQL特性
     */
    IPage<Map<String, Object>> selectPage(IPage<?> page,
                                           @Param("userId") String userId,
                                           @Param("status") String status);
}

package com.example.app.model;

import lombok.Data;

@Data
public class UserOrder {
    private String id;
    private String userId;
    private Double amount;
    private String status;
    private String createTime;
}

// MyBatis Plus配置类（简化）
@Configuration
public class MyBatisPlusConfig {
    @Bean
    public MybatisPlusInterceptor mybatisPlusInterceptor() {
        return new MybatisPlusInterceptor();
    }
}