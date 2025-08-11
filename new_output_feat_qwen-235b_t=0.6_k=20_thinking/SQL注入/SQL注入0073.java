package com.example.app.order;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class OrderService extends ServiceImpl<OrderMapper, Order> {
    private static final List<String> ALLOWED_STATUSES = Arrays.asList("pending", "completed", "cancelled");

    public List<Order> getOrders(String orderStatus, String[] ids) {
        if (!ALLOWED_STATUSES.contains(orderStatus)) {
            throw new IllegalArgumentException("Invalid order status");
        }
        
        QueryWrapper<Order> queryWrapper = new QueryWrapper<>();
        queryWrapper.eq("status", orderStatus);
        
        if (ids != null && ids.length > 0) {
            String idList = processIds(ids);
            queryWrapper.apply("id IN ({0})", idList);
        }
        
        return list(queryWrapper);
    }

    private String processIds(String[] ids) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < ids.length; i++) {
            if (i > 0) result.append(",");
            result.append(ids[i]);
        }
        return result.toString();
    }
}

interface OrderMapper extends com.baomidou.mybatisplus.core.mapper.BaseMapper<Order> {
    @Select("SELECT * FROM orders WHERE status = #{status} AND id IN (${ids})")
    List<Order> selectByCustomQuery(@Param("status") String status, @Param("ids") String ids);
}

@RestController
@RequestMapping("/orders")
class OrderController {
    private final OrderService orderService;

    public OrderController(OrderService orderService) {
        this.orderService = orderService;
    }

    @GetMapping
    public List<Order> getOrders(@RequestParam String status, @RequestParam(required = false) String[] ids) {
        return orderService.getOrders(status, ids);
    }
}

record Order(Long id, String status, Double amount) {}

// MyBatis Plus Configuration (simplified)
@Configuration
@MapperScan("com.example.app.order")
class MyBatisConfig {}