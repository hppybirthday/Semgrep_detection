package com.crm.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class CustomerService {
    @Autowired
    private CustomerMapper customerMapper;

    public int deleteCustomers(Map<String, Object> params) {
        List<Integer> ids = (List<Integer>) params.get("ids");
        String orderBy = Optional.ofNullable((String) params.get("order_by"))
                                .orElse("id");
        
        // 漏洞点：直接拼接ORDER BY参数
        String sql = "DELETE FROM customers WHERE id IN (" + String.join(",", ids.stream().map(String::valueOf).toArray(String[]::new)) + ") ORDER BY " + orderBy;
        
        return customerMapper.executeDynamicSQL(sql);
    }
}

package com.crm.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CustomerMapper {
    @Delete("${sql}") // 危险的${}替换方式
    int executeDynamicSQL(@Param("sql") String sql);
}

package com.crm.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/customers")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @DeleteMapping
    public int deleteCustomers(@RequestBody Map<String, Object> params) {
        return customerService.deleteCustomers(params);
    }
}

// MyBatis配置文件（简化版）
// mapper.xml中使用了直接拼接：
// <delete id="executeDynamicSQL">
//   ${sql}
// </delete>