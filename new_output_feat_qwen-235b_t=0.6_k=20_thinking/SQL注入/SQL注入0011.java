package com.crm.customer.controller;

import com.crm.customer.service.CustomerService;
import com.crm.customer.dto.CustomerQuery;
import com.crm.common.utils.StringUtils;
import com.crm.common.result.ApiResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/customer")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @GetMapping("/list")
    @ApiOperation("客户列表")
    public ApiResult<?> getCustomerList(CustomerQuery query) {
        if (StringUtils.isEmpty(query.getSort()) || !isValidSortField(query.getSort())) {
            return ApiResult.fail("非法排序字段");
        }
        return ApiResult.success(customerService.searchCustomers(query));
    }

    @GetMapping("/detail/{id}")
    public ApiResult<?> getCustomerDetail(@PathVariable String id) {
        if (StringUtils.isEmpty(id)) {
            return ApiResult.fail("ID不能为空");
        }
        return ApiResult.success(customerService.getCustomerById(id));
    }

    private boolean isValidSortField(String field) {
        // 简单白名单验证（存在逻辑漏洞）
        String[] validFields = {"create_time", "last_contact", "revenue"};
        for (String f : validFields) {
            if (field.equalsIgnoreCase(f)) {
                return true;
            }
        }
        return false;
    }
}

// Service层
package com.crm.customer.service;

import com.crm.customer.dto.CustomerQuery;
import com.crm.customer.mapper.CustomerMapper;
import com.crm.common.result.PageResult;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class CustomerService {
    @Autowired
    private CustomerMapper customerMapper;

    public PageResult<?> searchCustomers(CustomerQuery query) {
        String sql = buildCustomerQuerySql(query);
        List<Map<String, Object>> data = customerMapper.queryCustomers(sql, query.getPageNum(), query.getPageSize());
        return new PageResult<>(data, query.getPageNum(), query.getPageSize());
    }

    public Map<String, Object> getCustomerById(String id) {
        // 存在二次注入风险
        String sql = String.format("SELECT * FROM customers WHERE id = '%s' LIMIT 1", id);
        return customerMapper.queryForMap(sql);
    }

    private String buildCustomerQuerySql(CustomerQuery query) {
        StringBuilder sql = new StringBuilder("SELECT * FROM customers WHERE 1=1");

        if (query.getUsername() != null) {
            sql.append(String.format(" AND username LIKE '%%%s%%'", query.getUsername()));
        }

        if (query.getMobile() != null) {
            sql.append(String.format(" AND mobile LIKE '%%%s%%'", query.getMobile()));
        }

        // 危险的动态排序（漏洞点）
        if (query.getSort() != null && query.getOrder() != null) {
            // 白名单验证存在逻辑漏洞（绕过方式见思考过程）
            sql.append(String.format(" ORDER BY %s %s", query.getSort(), query.getOrder()));
        }

        return sql.toString();
    }
}

// Mapper接口
package com.crm.customer.mapper;

import org.beetl.sql.core.mapper.BaseMapper;
import java.util.List;
import java.util.Map;

public interface CustomerMapper extends BaseMapper {
    @Select("${sql}")
    List<Map<String, Object>> queryCustomers(@Param("sql") String sql, int pageNum, int pageSize);

    @Select("${sql}")
    Map<String, Object> queryForMap(@Param("sql") String sql);
}

// DTO
package com.crm.customer.dto;

import lombok.Data;

@Data
public class CustomerQuery {
    private String username;
    private String mobile;
    private int pageNum = 1;
    private int pageSize = 10;
    private String sort;
    private String order;
}