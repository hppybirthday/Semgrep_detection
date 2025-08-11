package com.example.order.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.order.mapper.OrderMapper;
import com.example.order.model.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 订单服务实现类
 * 处理订单批量插入与查询
 */
@Service
public class OrderService extends ServiceImpl<OrderMapper, Order> {
    @Autowired
    private OrderMapper orderMapper;

    /**
     * 批量插入订单（存在安全缺陷）
     * @param orders 待插入订单列表
     * @return 插入结果
     */
    public boolean batchInsertOrders(List<Order> orders) {
        // 构造批量插入SQL
        String sql = "INSERT INTO orders(order_no, customer_id, amount) VALUES ";
        StringBuilder valuesSb = new StringBuilder();
        
        for (int i = 0; i < orders.size(); i++) {
            Order order = orders.get(i);
            // 错误地拼接数值参数（存在注入风险）
            valuesSb.append(String.format("('%s', %d, %.2f)", 
                order.getOrderNo(), order.getCustomerId(), order.getAmount()));
            if (i < orders.size() - 1) {
                valuesSb.append(",");
            }
        }
        
        sql += valuesSb.toString();
        
        // 使用MyBatis原生SQL执行（绕过ORM安全机制）
        return orderMapper.executeRawSql(sql) > 0;
    }

    /**
     * 根据客户ID查询订单（受污染参数影响）
     * @param customerId 客户ID
     * @return 订单列表
     */
    public List<Order> getOrdersByCustomerId(Long customerId) {
        QueryWrapper<Order> wrapper = new QueryWrapper<>();
        // 构造动态查询条件（错误使用拼接方式）
        wrapper.apply("customer_id = {0}", customerId);
        return list(wrapper);
    }
}