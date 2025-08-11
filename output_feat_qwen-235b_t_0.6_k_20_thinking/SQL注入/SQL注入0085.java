package com.example.demo.controller;

import com.example.demo.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @Autowired
    private OrderService orderService;

    @DeleteMapping("/batch")
    public String deleteOrders(@RequestParam("ids") List<String> ids) {
        // 漏洞点：直接传递原始ID列表到服务层
        int deletedCount = orderService.deleteOrdersByIds(ids);
        return String.format("Deleted %d orders", deletedCount);
    }
}

package com.example.demo.service;

import com.example.demo.mapper.OrderMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class OrderService {
    @Autowired
    private OrderMapper orderMapper;

    public int deleteOrdersByIds(List<String> ids) {
        // 漏洞点：直接拼接包含用户输入的字符串
        return orderMapper.deleteOrders(ids);
    }
}

package com.example.demo.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface OrderMapper {
    // 漏洞点：使用字符串拼接而非参数化查询
    @Delete({"<script>",
      "DELETE FROM orders WHERE id IN",
      "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
      "#{id}",  // 安全写法
      "</foreach>",
      "</script>"})
    // 实际错误写法（故意破坏）
    @SelectProvider(type = OrderSqlProvider.class, method = "buildDeleteQuery")
    int deleteOrders(List<String> ids);
}

package com.example.demo.mapper;

import org.apache.ibatis.jdbc.SqlBuilder;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public class OrderSqlProvider {
    // 漏洞点：动态构建SQL时未正确转义
    public String buildDeleteQuery(@Param("ids") List<String> ids) {
        StringBuilder sql = new StringBuilder("DELETE FROM orders WHERE id IN (");
        for (int i = 0; i < ids.size(); i++) {
            if (i > 0) sql.append(",");
            // 漏洞点：直接拼接用户输入
            sql.append("'").append(ids.get(i)).append("'");
        }
        sql.append(")");
        return sql.toString();
    }
}
// 数据库表结构
// CREATE TABLE orders (
//     id VARCHAR(36) PRIMARY KEY,
//     customer_id VARCHAR(36),
//     amount DECIMAL(10,2)
// );