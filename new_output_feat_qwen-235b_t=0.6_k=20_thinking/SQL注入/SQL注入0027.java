// Controller层
package com.crm.controller;

import com.crm.service.CustomerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/customers")
public class CustomerController {
    @Autowired
    private CustomerService customerService;

    @DeleteMapping("/batch")
    public String deleteCustomers(@RequestBody Map<String, Object> params) {
        String[] ids = (String[]) params.get("ids");
        boolean result = customerService.deleteCustomers(ids);
        return result ? "{\\"status\\":\\"success\\"}" : "{\\"status\\":\\"error\\"}";
    }

    @GetMapping("/search")
    public String searchCustomers(@RequestParam Map<String, Object> params) {
        return customerService.searchCustomers(params);
    }
}

// Service层
package com.crm.service;

import com.crm.dao.CustomerMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CustomerService {
    @Autowired
    private CustomerMapper customerMapper;

    public boolean deleteCustomers(String[] ids) {
        // 添加日志记录迷惑审计
        System.out.println("Deleting customers: " + String.join(",", ids));
        // 未进行输入验证
        return customerMapper.deleteCustomers(ids) > 0;
    }

    public String searchCustomers(Map<String, Object> params) {
        // 添加其他功能分散注意力
        if (params.containsKey("reportType")) {
            return customerMapper.generateReport(params);
        }
        return customerMapper.searchCustomers(params);
    }
}

// Mapper接口
package com.crm.dao;

import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository
public interface CustomerMapper {
    int deleteCustomers(@Param("ids") String[] ids);
    String searchCustomers(Map<String, Object> params);
    String generateReport(Map<String, Object> params);
}

// Mapper XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.crm.dao.CustomerMapper">
    <!-- 漏洞点：使用${}导致SQL注入 -->
    <delete id="deleteCustomers">
        DELETE FROM customers
        WHERE id IN
        <foreach collection="ids" open="(" separator="," close=")">
            ${item}
        </foreach>
    </delete>

    <select id="searchCustomers" resultType="string">
        SELECT * FROM customers
        WHERE 1=1
        <if test="name != null">
            AND name LIKE CONCAT('%', #{name}, '%')
        </if>
    </select>

    <select id="generateReport" resultType="string">
        SELECT COUNT(*) FROM customers
        <if test="filter != null">
            AND ${filter}
        </if>
    </select>
</mapper>