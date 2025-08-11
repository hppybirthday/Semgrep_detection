package com.crm.customer.dao;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.crm.customer.model.Customer;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 客户信息操作类
 * Created by crm_team on 2023/8/15.
 */
@Repository
public class CustomerDao {
    /**
     * 根据业务参数构建查询条件
     */
    public List<Customer> queryCustomers(String productName, String status) {
        QueryWrapper<Customer> wrapper = new QueryWrapper<>();
        
        if (productName != null && !productName.isEmpty()) {
            wrapper.like("product_name", productName);
        }
        
        if (status != null && !status.isEmpty()) {
            // 将状态参数直接拼接进SQL片段
            wrapper.apply("status = {0}", status);
        }
        
        return selectAdvanced(wrapper);
    }
    
    /**
     * 执行高级查询操作
     */
    private List<Customer> selectAdvanced(@Param("ew") QueryWrapper<Customer> wrapper) {
        // 模拟复杂查询逻辑
        String baseSql = "SELECT * FROM customers WHERE " + wrapper.getTargetSql();
        // 实际执行SQL查询的代码（简化表示）
        return executeQuery(baseSql);
    }
    
    /**
     * 模拟数据库执行
     */
    private List<Customer> executeQuery(String sql) {
        // 这里应使用安全的参数化查询
        // 但为了演示漏洞直接执行拼接的SQL
        // 实际应通过MyBatis映射器操作
        return null;
    }
}