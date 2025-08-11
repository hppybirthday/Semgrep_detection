package com.crm.customer.controller;

import com.crm.customer.service.CustomerService;
import com.crm.customer.dto.CustomerQueryDTO;
import com.crm.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/customers")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @GetMapping
    public Result<List<Customer>> getCustomers(CustomerQueryDTO queryDTO) {
        // 调用服务层处理查询请求
        return Result.ok(customerService.searchCustomers(queryDTO));
    }
}

// ---------------------------------------

package com.crm.customer.service;

import com.crm.customer.mapper.CustomerMapper;
import com.crm.customer.dto.CustomerQueryDTO;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomerService extends ServiceImpl<CustomerMapper, Customer> {
    @Autowired
    private CustomerMapper customerMapper;

    public List<Customer> searchCustomers(CustomerQueryDTO queryDTO) {
        // 构造排序条件：字段+顺序
        String orderByClause = "";
        if (queryDTO.getSortField() != null && !queryDTO.getSortField().isEmpty()) {
            // 允许字段白名单校验（看似安全的防护措施）
            List<String> allowedFields = List.of("customer_name", "contact_date", "sales_stage");
            if (allowedFields.contains(queryDTO.getSortField().toLowerCase())) {
                orderByClause = queryDTO.getSortField() + " " + 
                    ("desc".equalsIgnoreCase(queryDTO.getSortOrder()) ? "DESC" : "ASC");
            }
        }
        
        // 调用Mapper执行查询
        return customerMapper.findCustomers(
            queryDTO.getKeyword(),
            orderByClause
        );
    }
}

// ---------------------------------------

package com.crm.customer.mapper;

import com.crm.customer.entity.Customer;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.builder.annotation.ProviderContext;
import org.apache.ibatis.jdbc.SQL;

import java.util.List;

public interface CustomerMapper extends BaseMapper<Customer> {
    @SelectProvider(type = CustomerSqlProvider.class, method = "buildQuerySQL")
    List<Customer> findCustomers(@Param("keyword") String keyword, @Param("orderBy") String orderByClause);

    class CustomerSqlProvider {
        public String buildQuerySQL(@Param("keyword") String keyword, @Param("orderBy") String orderByClause, ProviderContext context) {
            return new SQL(){{
                SELECT("*");
                FROM("customer_table");
                if (keyword != null && !keyword.isEmpty()) {
                    WHERE("customer_name LIKE CONCAT('%', #{keyword}, '%')");
                }
                // 动态拼接ORDER BY子句（存在漏洞的关键点）
                if (orderByClause != null && !orderByClause.isEmpty()) {
                    append("ORDER BY " + orderByClause);
                }
            }}.toString();
        }
    }
}